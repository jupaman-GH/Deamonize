//! Collects precise metadata for every Windows service via the Service
//! Control Manager (SCM) API, then enriches binaries with SHA-256 hashes,
//! Authenticode signature status and PE version info.

use std::collections::HashMap;
use std::path::Path;

use sha2::{Digest, Sha256};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertFreeCertificateContext, CertGetNameStringW, CryptQueryObject,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_CERT,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
    CERT_QUERY_OBJECT_FILE, HCERTSTORE,
};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::Win32::System::Services::{
    EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, CloseServiceHandle,
    QueryServiceConfig2W, QueryServiceConfigW, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DESCRIPTIONW, SERVICE_QUERY_CONFIG,
    SERVICE_STATE_ALL, SERVICE_WIN32,
};

use crate::models::{ServiceInfo, ServiceKind, ServiceStatus, StartType};

/// Collects all Win32 services with full metadata.
pub fn collect_services() -> Result<Vec<ServiceInfo>, String> {
    let raw = enumerate_scm()?;
    let mut hash_cache: HashMap<String, Option<String>> = HashMap::new();
    Ok(raw.into_iter().map(|s| enrich_binary(s, &mut hash_cache)).collect())
}

struct RawService {
    name: String,
    display_name: String,
    description: Option<String>,
    pid: Option<i64>,
    status: ServiceStatus,
    start_type: StartType,
    delayed_auto: bool,
    service_type: u32,
    account: Option<String>,
    bin_path: Option<String>,
    dependencies: Vec<String>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn pstr(p: PWSTR) -> Option<String> {
    if p.is_null() {
        None
    } else {
        let s = unsafe { p.to_string() }.unwrap_or_default();
        if s.is_empty() { None } else { Some(s) }
    }
}

fn map_status(v: u32) -> ServiceStatus {
    match v {
        1 => ServiceStatus::Stopped,
        2 => ServiceStatus::StartPending,
        3 => ServiceStatus::StopPending,
        4 => ServiceStatus::Running,
        5 => ServiceStatus::ContinuePending,
        6 => ServiceStatus::PausePending,
        7 => ServiceStatus::Paused,
        _ => ServiceStatus::Unknown,
    }
}

fn map_start_type(v: u32) -> StartType {
    match v {
        0 => StartType::Boot,
        1 => StartType::System,
        2 => StartType::Auto,
        3 => StartType::Demand,
        4 => StartType::Disabled,
        _ => StartType::Unknown,
    }
}

fn map_kind(v: u32) -> ServiceKind {
    if v & 0x10 != 0 {
        ServiceKind::Own
    } else if v & 0x20 != 0 {
        ServiceKind::Share
    } else if v & 0x01 != 0 {
        ServiceKind::Kernel
    } else if v & 0x02 != 0 {
        ServiceKind::Filesystem
    } else if v & 0x08 != 0 {
        ServiceKind::Recognition
    } else if v & 0x04 != 0 {
        ServiceKind::Driver
    } else {
        ServiceKind::Unknown
    }
}

/// Reads a REG_MULTI_SZ block (double-null-terminated) into Vec<String>.
unsafe fn read_multi_sz(p: PWSTR) -> Vec<String> {
    let mut out = Vec::new();
    if p.is_null() {
        return out;
    }
    let mut cur = p;
    loop {
        let s = unsafe { pstr(cur) };
        match s {
            Some(s) => {
                let len = s.encode_utf16().count();
                out.push(s);
                cur = PWSTR(unsafe { cur.0.add(len + 1) });
            }
            None => break,
        }
    }
    out
}

fn enumerate_scm() -> Result<Vec<RawService>, String> {
    unsafe {
        let scm = OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        )
        .map_err(|e| format!("OpenSCManager failed: {e}"))?;

        // First call: query required buffer size.
        let mut bytes_needed: u32 = 0;
        let mut count: u32 = 0;
        let mut resume: u32 = 0;
        let _ = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut bytes_needed,
            &mut count,
            Some(&mut resume),
            PCWSTR::null(),
        );
        if bytes_needed == 0 {
            let _ = CloseServiceHandle(scm);
            return Err("EnumServicesStatusEx returned no data".into());
        }

        let mut buf: Vec<u8> = vec![0; bytes_needed as usize];
        resume = 0;
        count = 0;
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(&mut buf),
            &mut bytes_needed,
            &mut count,
            Some(&mut resume),
            PCWSTR::null(),
        )
        .map_err(|e| format!("EnumServicesStatusEx failed: {e}"))?;

        let entries =
            std::slice::from_raw_parts(buf.as_ptr() as *const ServiceStatusEntry, count as usize);

        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let name = pstr(PWSTR(e.name)).unwrap_or_default();
            let display_name = pstr(PWSTR(e.display)).unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let wname = wide(&name);
            let svc = OpenServiceW(scm, PCWSTR(wname.as_ptr()), SERVICE_QUERY_CONFIG).ok();

            let mut description = None;
            let mut start_type = StartType::Unknown;
            let mut delayed_auto = false;
            let mut account = None;
            let mut bin_path = None;
            let mut dependencies = Vec::new();

            if let Some(svc) = svc {
                // Basic config: the QUERY_SERVICE_CONFIGW struct is followed
                // inline by its strings, so query the needed size first and
                // allocate a big enough buffer.
                let mut needed: u32 = 0;
                let _ = QueryServiceConfigW(svc, None, 0, &mut needed);
                if needed > 0 {
                    let mut cbuf: Vec<u8> = vec![0; needed as usize];
                    if QueryServiceConfigW(svc, Some(cbuf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW), needed, &mut needed).is_ok() {
                        let cfg = &*(cbuf.as_ptr() as *const QUERY_SERVICE_CONFIGW);
                        start_type = map_start_type(cfg.dwStartType.0);
                        bin_path = unsafe { pstr(cfg.lpBinaryPathName) };
                        account = unsafe { pstr(cfg.lpServiceStartName) };
                        dependencies = unsafe { read_multi_sz(cfg.lpDependencies) };
                    }
                }

                // Description.
                let mut dneeded: u32 = 0;
                let _ = QueryServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, None, &mut dneeded);
                if dneeded > 0 {
                    let mut dbuf: Vec<u8> = vec![0; dneeded as usize];
                    if QueryServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, Some(&mut dbuf), &mut dneeded).is_ok() {
                        let d = &*(dbuf.as_ptr() as *const SERVICE_DESCRIPTIONW);
                        description = unsafe { pstr(d.lpDescription) };
                    }
                }

                // Delayed auto-start.
                let mut lneeded: u32 = 0;
                let _ = QueryServiceConfig2W(svc, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, None, &mut lneeded);
                if lneeded > 0 {
                    let mut lbuf: Vec<u8> = vec![0; lneeded as usize];
                    if QueryServiceConfig2W(svc, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, Some(&mut lbuf), &mut lneeded).is_ok() {
                        let l = &*(lbuf.as_ptr() as *const SERVICE_DELAYED_AUTO_START_INFO);
                        delayed_auto = l.fDelayedAutostart.as_bool();
                    }
                }

                let _ = CloseServiceHandle(svc);
            }

            let status = map_status(e.status.dwCurrentState.0);
            let pid = if e.status.dwProcessId != 0 {
                Some(e.status.dwProcessId as i64)
            } else {
                None
            };
            let service_type = e.status.dwServiceType.0;

            out.push(RawService {
                name,
                display_name,
                description,
                pid,
                status,
                start_type,
                delayed_auto,
                service_type,
                account,
                bin_path,
                dependencies,
            });
        }

        let _ = CloseServiceHandle(scm);
        Ok(out)
    }
}

#[repr(C)]
struct ServiceStatusEntry {
    name: *mut u16,
    display: *mut u16,
    status: windows::Win32::System::Services::SERVICE_STATUS_PROCESS,
}

fn exe_from_bin_path(bin_path: &str) -> Option<String> {
    let trimmed = bin_path.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    let lower = trimmed.to_lowercase();
    if let Some(pos) = lower.find(".exe") {
        return Some(trimmed[..pos + 4].to_string());
    }
    Some(trimmed.split_whitespace().next().unwrap_or(trimmed).to_string())
}

fn expand_env(path: &str) -> String {
    let chars: Vec<char> = path.chars().collect();
    let mut out = String::with_capacity(path.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' {
            if let Some(rel) = chars[i + 1..].iter().position(|&c| c == '%') {
                let varname: String = chars[i + 1..i + 1 + rel].iter().collect();
                if !varname.is_empty() {
                    if let Ok(val) = std::env::var(&varname) {
                        out.push_str(&val);
                        i += rel + 2;
                        continue;
                    }
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn sha256_of_file(path: &str) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}

/// Returns (signed, signer_subject, status_detail).
fn verify_signature(path: &str) -> (Option<bool>, Option<String>, Option<String>) {
    unsafe {
        let wpath = wide(path);
        let mut store: HCERTSTORE = HCERTSTORE::default();
        let mut ctx_ptr: *mut core::ffi::c_void = std::ptr::null_mut();

        let ok = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wpath.as_ptr() as *const _,
            windows::Win32::Security::Cryptography::CERT_QUERY_CONTENT_TYPE_FLAGS(
                CERT_QUERY_CONTENT_FLAG_CERT.0 | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED.0,
            ),
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store),
            None,
            Some(&mut ctx_ptr),
        );
        if ok.is_err() || ctx_ptr.is_null() {
            return (Some(false), None, Some("unsigned".into()));
        }

        let ctx = ctx_ptr as *const windows::Win32::Security::Cryptography::CERT_CONTEXT;
        let mut name_buf = [0u16; 512];
        let len = CertGetNameStringW(
            ctx,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name_buf),
        );
        let signer = if len > 1 {
            Some(String::from_utf16_lossy(&name_buf[..len as usize - 1]))
        } else {
            None
        };

        let _ = CertFreeCertificateContext(Some(ctx));
        if !store.is_invalid() {
            let _ = CertCloseStore(Some(store), 0);
        }
        (Some(true), signer, Some("signed".into()))
    }
}

fn get_version_info(path: &str) -> (Option<String>, Option<String>, Option<String>, Option<String>, Option<String>) {
    unsafe {
        let wpath = wide(path);
        let mut handle = 0u32;
        let size = GetFileVersionInfoSizeW(PCWSTR(wpath.as_ptr()), Some(&mut handle));
        if size == 0 {
            return (None, None, None, None, None);
        }
        let mut buf = vec![0u8; size as usize];
        if GetFileVersionInfoW(PCWSTR(wpath.as_ptr()), None, size, buf.as_mut_ptr() as *mut _).is_err() {
            return (None, None, None, None, None);
        }

        let mut trans_len = 0u32;
        let mut trans_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let sub = wide("\\VarFileInfo\\Translation");
        let has_trans = VerQueryValueW(
            buf.as_ptr() as *const _,
            PCWSTR(sub.as_ptr()),
            &mut trans_ptr,
            &mut trans_len,
        )
        .as_bool()
            && trans_len >= 4;
        let (lang, codepage) = if has_trans {
            let t = trans_ptr as *const u16;
            ((*t as u32), (*t.add(1) as u32))
        } else {
            (0x0409, 0x04B0)
        };

        let get_str = |name: &str| -> Option<String> {
            let subpath = format!("\\StringFileInfo\\{lang:04x}{codepage:04x}\\{name}");
            let wsub = wide(&subpath);
            let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
            let mut len = 0u32;
            if VerQueryValueW(buf.as_ptr() as *const _, PCWSTR(wsub.as_ptr()), &mut ptr, &mut len).as_bool()
                && !ptr.is_null()
                && len > 1
            {
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(ptr as *const u16, len as usize - 1));
                if s.trim().is_empty() { None } else { Some(s.trim().to_string()) }
            } else {
                None
            }
        };

        let company = get_str("CompanyName");
        let product = get_str("ProductName");
        let file_description = get_str("FileDescription");
        let original_filename = get_str("OriginalFilename");
        let file_version = get_str("FileVersion");
        (company, product, file_description, original_filename, file_version)
    }
}

fn enrich_binary(svc: RawService, cache: &mut HashMap<String, Option<String>>) -> ServiceInfo {
    let exe = svc
        .bin_path
        .as_deref()
        .and_then(exe_from_bin_path)
        .map(|p| expand_env(&p));

    let mut sha256 = None;
    let mut signed = None;
    let mut signer = None;
    let mut signature_status = None;
    let mut company = None;
    let mut product = None;
    let mut file_description = None;
    let mut original_filename = None;
    let mut file_version = None;

    if let Some(ref exe_path) = exe {
        if Path::new(exe_path).exists() {
            sha256 = cache
                .entry(exe_path.clone())
                .or_insert_with(|| sha256_of_file(exe_path))
                .clone();
            let (s, subj, st) = verify_signature(exe_path);
            signed = s;
            signer = subj;
            signature_status = st;
            let (c, p, fd, of, fv) = get_version_info(exe_path);
            company = c;
            product = p;
            file_description = fd;
            original_filename = of;
            file_version = fv;
        } else {
            signature_status = Some("file_not_found".into());
        }
    }

    ServiceInfo {
        name: svc.name,
        display_name: svc.display_name,
        description: svc.description,
        pid: svc.pid,
        status: svc.status,
        start_type: if svc.delayed_auto && svc.start_type == StartType::Auto {
            StartType::DelayedAuto
        } else {
            svc.start_type
        },
        kind: map_kind(svc.service_type),
        account: svc.account,
        bin_path: svc.bin_path,
        exe_path: exe,
        dll_path: None,
        dependencies: svc.dependencies,
        sha256,
        signed,
        signer,
        signature_status,
        company,
        product,
        file_description,
        original_filename,
        file_version,
    }
}

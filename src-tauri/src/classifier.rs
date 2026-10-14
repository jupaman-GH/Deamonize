//! Local rules engine: classifies services by evaluating hash > path > signer
//! > name rules with confidence and explainable reasons.

use crate::models::{Rule, ServiceInfo, Verdict, VerdictCategory, VerdictReason};

/// Weights per rule kind, by priority (higher wins when several match).
const KIND_PRIORITY: &[(&str, i64)] = &[("hash", 400), ("path", 300), ("signer", 200), ("name", 100)];

/// Base confidence per matched rule kind.
fn base_confidence(kind: &str) -> f64 {
    match kind {
        "hash" => 0.95,
        "signer" => 0.90,
        "path" => 0.85,
        "name" => 0.80,
        _ => 0.6,
    }
}

fn kind_rank(kind: &str) -> i64 {
    KIND_PRIORITY
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, p)| *p)
        .unwrap_or(0)
}

fn matches(rule: &Rule, svc: &ServiceInfo) -> bool {
    match rule.kind.as_str() {
        "hash" => svc
            .sha256
            .as_deref()
            .map(|h| h.eq_ignore_ascii_case(&rule.pattern))
            .unwrap_or(false),
        "name" => {
            svc.name.eq_ignore_ascii_case(&rule.pattern)
                || svc.display_name.eq_ignore_ascii_case(&rule.pattern)
        }
        "signer" => svc
            .signer
            .as_deref()
            .map(|s| s.to_lowercase().contains(&rule.pattern.to_lowercase()))
            .unwrap_or(false),
        "path" => {
            let haystack = svc
                .exe_path
                .as_deref()
                .or(svc.bin_path.as_deref())
                .unwrap_or("")
                .to_lowercase();
            let pat = rule.pattern.to_lowercase();
            // A path rule like "C:\Temp\*" becomes a prefix match.
            if let Some(prefix) = pat.strip_suffix('*') {
                haystack.starts_with(prefix.trim_end_matches('\\'))
            } else {
                haystack.contains(&pat)
            }
        }
        _ => false,
    }
}

const SOURCE_LEARN_SERVICE_GUIDE: &str =
    "https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server";

/// Classifies a service against the enabled rules.
///
/// Rules are evaluated with priority hash > path > signer > name; the first
/// (highest-priority) match defines the category, but a `dangerous` match of
/// ANY kind always wins over safe matches (blacklist beats whitelist).
pub fn classify(svc: &ServiceInfo, rules: &[Rule]) -> Verdict {
    let mut reasons: Vec<VerdictReason> = Vec::new();
    let mut best: Option<&Rule> = None;
    let mut blacklisted: Option<&Rule> = None;

    for rule in rules.iter().filter(|r| r.enabled) {
        if matches(rule, svc) {
            match rule.category {
                VerdictCategory::Dangerous => {
                    if blacklisted
                        .map(|b| kind_rank(&rule.kind) >= kind_rank(&b.kind))
                        .unwrap_or(true)
                    {
                        blacklisted = Some(rule);
                    }
                }
                _ => {
                    if best
                        .map(|b| kind_rank(&rule.kind) > kind_rank(&b.kind))
                        .unwrap_or(true)
                    {
                        best = Some(rule);
                    }
                }
            }
        }
    }

    let (category, confidence, source_url) = if let Some(rule) = blacklisted {
        reasons.push(VerdictReason {
            code: format!("rule.{}.blacklist", rule.kind),
            message: match rule.kind.as_str() {
                "hash" => "El hash del binario coincide con una entrada de la lista negra.",
                "path" => "La ruta del binario coincide con una entrada de la lista negra.",
                "signer" => "El firmante del binario coincide con una entrada de la lista negra.",
                _ => "El nombre del servicio coincide con una entrada de la lista negra.",
            }
            .to_string(),
            detail: Some(rule.pattern.clone()),
            weight: 1.0,
        });
        (VerdictCategory::Dangerous, base_confidence(&rule.kind), None)
    } else if let Some(rule) = best {
        reasons.push(VerdictReason {
            code: format!("rule.{}.whitelist", rule.kind),
            message: match rule.kind.as_str() {
                "hash" => "El hash del binario coincide con una entrada conocida segura.",
                "path" => "La ruta del binario coincide con una entrada conocida segura.",
                "signer" => "El firmante del binario es un editor de confianza.",
                _ => "El nombre del servicio es una entrada conocida segura.",
            }
            .to_string(),
            detail: Some(rule.pattern.clone()),
            weight: -1.0,
        });
        (rule.category, base_confidence(&rule.kind), None)
    } else {
        // No rule matched: apply cheap local heuristics so the user gets a
        // provisional category instead of a blank "unknown".
        let mut suspicious_score = 0.0f64;

        if let Some(exe) = svc.exe_path.as_deref() {
            let low = exe.to_lowercase();
            if low.contains("\\temp\\")
                || low.contains("\\tmp\\")
                || low.contains("\\appdata\\")
                || low.contains("\\downloads\\")
                || low.contains("\\public\\")
            {
                suspicious_score += 0.5;
                reasons.push(VerdictReason {
                    code: "heuristic.location".into(),
                    message: "El binario se ejecuta desde una carpeta de usuario o temporal.".into(),
                    detail: Some(exe.to_string()),
                    weight: 0.5,
                });
            }
        }

        if svc.signed == Some(false) && svc.kind == crate::models::ServiceKind::Own {
            suspicious_score += 0.2;
            reasons.push(VerdictReason {
                code: "heuristic.unsigned".into(),
                message: "El binario no tiene firma digital.".into(),
                detail: None,
                weight: 0.2,
            });
        }

        // Lookalike of a system process/service name.
        const SYSTEM_NAMES: &[&str] = &[
            "svchost", "csrss", "lsass", "services", "winlogon", "explorer", "system", "smss",
            "spoolsv", "taskhost",
        ];
        let lname = svc.name.to_lowercase();
        if SYSTEM_NAMES.iter().any(|s| lname.contains(s)) && svc.signed != Some(true) {
            suspicious_score += 0.6;
            reasons.push(VerdictReason {
                code: "heuristic.lookalike".into(),
                message: "El nombre imita a un proceso o servicio del sistema y no está firmado.".into(),
                detail: Some(svc.name.clone()),
                weight: 0.6,
            });
        }

        // ---- Fase 4: detección de suplantación y firmas ---

        // OriginalFileName mismatch: the PE says one thing, the file on disk
        // another. Classic masquerade technique.
        if let (Some(orig), Some(exe)) = (svc.original_filename.as_deref(), svc.exe_path.as_deref()) {
            let exe_file = exe
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or("")
                .to_lowercase();
            let orig_lower = orig.to_lowercase();
            if !exe_file.is_empty()
                && !orig_lower.is_empty()
                && exe_file != orig_lower
                && !SYSTEM_NAMES.iter().any(|s| exe_file.contains(s))
            {
                suspicious_score += 0.4;
                reasons.push(VerdictReason {
                    code: "spoof.original_filename_mismatch".into(),
                    message: "El nombre original del binario (PE) no coincide con el archivo en disco.".into(),
                    detail: Some(format!("disco={exe_file} vs pe={orig_lower}")),
                    weight: 0.4,
                });
            }
        }

        // Claims to be Microsoft but is not signed by Microsoft.
        if let Some(company) = svc.company.as_deref() {
            let claims_ms = company.to_lowercase().contains("microsoft");
            let ms_signed = svc
                .signer
                .as_deref()
                .map(|s| s.to_lowercase().contains("microsoft"))
                .unwrap_or(false);
            if claims_ms && svc.signed != Some(true) {
                suspicious_score += 0.7;
                reasons.push(VerdictReason {
                    code: "spoof.claims_microsoft_unsigned".into(),
                    message: "Dice ser de Microsoft pero el binario no está firmado.".into(),
                    detail: Some(company.to_string()),
                    weight: 0.7,
                });
            } else if claims_ms && !ms_signed {
                suspicious_score += 0.5;
                reasons.push(VerdictReason {
                    code: "spoof.claims_microsoft_other_signer".into(),
                    message: "Dice ser de Microsoft pero el firmante es otro.".into(),
                    detail: Some(svc.signer.clone().unwrap_or_default()),
                    weight: 0.5,
                });
            }
        }

        // Unquoted service path with spaces (hijackable).
        if let Some(bin) = svc.bin_path.as_deref() {
            if !bin.starts_with('"') && bin.contains(' ') && bin.to_lowercase().contains(".exe") {
                suspicious_score += 0.3;
                reasons.push(VerdictReason {
                    code: "heuristic.unquoted_path".into(),
                    message: "Ruta del servicio sin comillas y con espacios (vulnerable a secuestro).".into(),
                    detail: Some(bin.to_string()),
                    weight: 0.3,
                });
            }
        }

        if suspicious_score >= 0.5 {
            (
                VerdictCategory::Suspicious,
                (0.4 + suspicious_score * 0.4).min(0.75),
                Some(SOURCE_LEARN_SERVICE_GUIDE.to_string()),
            )
        } else {
            reasons.push(VerdictReason {
                code: "rule.none".into(),
                message: "Sin coincidencias en las listas locales; veredicto pendiente de consulta.".into(),
                detail: None,
                weight: 0.0,
            });
            (VerdictCategory::Unknown, 0.3, None)
        }
    };

    Verdict {
        service: svc.name.clone(),
        category,
        confidence,
        reasons,
        source: "local".into(),
        source_url,
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// Builds a fixture ServiceInfo for tests.
#[cfg(test)]
fn fixture(name: &str, exe: Option<&str>, signed: Option<bool>, signer: Option<&str>) -> ServiceInfo {
    ServiceInfo {
        name: name.into(),
        display_name: name.into(),
        description: None,
        pid: None,
        status: crate::models::ServiceStatus::Running,
        start_type: crate::models::StartType::Auto,
        kind: crate::models::ServiceKind::Own,
        account: None,
        bin_path: exe.map(|e| e.to_string()),
        exe_path: exe.map(|e| e.to_string()),
        dll_path: None,
        dependencies: vec![],
        sha256: None,
        signed,
        signer: signer.map(|s| s.into()),
        signature_status: None,
        company: None,
        product: None,
        file_description: None,
        original_filename: None,
        file_version: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Rule, VerdictCategory};

    fn rule(kind: &str, pattern: &str, category: VerdictCategory) -> Rule {
        Rule {
            id: 1,
            kind: kind.into(),
            pattern: pattern.into(),
            category,
            priority: 100,
            enabled: true,
            note: None,
        }
    }

    #[test]
    fn whitelist_name_is_safe() {
        let svc = fixture("AudioSrv", Some(r"C:\Windows\System32\svchost.exe"), Some(true), Some("Microsoft Windows"));
        let rules = vec![rule("name", "AudioSrv", VerdictCategory::Safe)];
        let v = classify(&svc, &rules);
        assert_eq!(v.category, VerdictCategory::Safe);
        assert!(v.confidence >= 0.8);
        assert!(!v.reasons.is_empty());
    }

    #[test]
    fn blacklist_name_is_dangerous_even_if_whitelisted_signer() {
        let svc = fixture("EvilSvc", Some(r"C:\x\evil.exe"), Some(true), Some("Microsoft Windows"));
        let rules = vec![
            rule("signer", "Microsoft", VerdictCategory::Safe),
            rule("name", "EvilSvc", VerdictCategory::Dangerous),
        ];
        let v = classify(&svc, &rules);
        // Blacklist by name beats whitelisted signer.
        assert_eq!(v.category, VerdictCategory::Dangerous);
    }

    #[test]
    fn temp_path_is_suspicious() {
        let svc = fixture("susp", Some(r"C:\Users\bob\AppData\Local\Temp\x.exe"), None, None);
        let v = classify(&svc, &[]);
        assert_eq!(v.category, VerdictCategory::Suspicious);
        assert!(v.reasons.iter().any(|r| r.code == "heuristic.location"));
    }

    #[test]
    fn unsigned_system_lookalike_is_suspicious() {
        let svc = fixture("svchostp", Some(r"C:\Windows\svchostp.exe"), Some(false), None);
        let v = classify(&svc, &[]);
        assert_eq!(v.category, VerdictCategory::Suspicious);
        assert!(v.reasons.iter().any(|r| r.code == "heuristic.lookalike"));
    }

    #[test]
    fn claims_microsoft_but_unsigned_is_suspicious() {
        let mut svc = fixture("fakems", Some(r"C:\fakems.exe"), Some(false), None);
        svc.company = Some("Microsoft Corporation".into());
        let v = classify(&svc, &[]);
        assert_eq!(v.category, VerdictCategory::Suspicious);
        assert!(v.reasons.iter().any(|r| r.code == "spoof.claims_microsoft_unsigned"));
    }

    #[test]
    fn summarize_counts_all_categories() {
        let svc = fixture("a", None, None, None);
        let verdicts = vec![
            classify(&svc, &[rule("name", "a", VerdictCategory::Safe)]),
            classify(&svc, &[rule("name", "a", VerdictCategory::Dangerous)]),
        ];
        let (safe, _susp, dangerous, _unk) = summarize(&verdicts);
        assert_eq!(safe, 1);
        assert_eq!(dangerous, 1);
    }
}

/// Summary counters for a set of verdicts.
pub fn summarize(verdicts: &[Verdict]) -> (i64, i64, i64, i64) {
    let mut safe = 0;
    let mut suspicious = 0;
    let mut dangerous = 0;
    let mut unknown = 0;
    for v in verdicts {
        match v.category {
            VerdictCategory::Safe => safe += 1,
            VerdictCategory::Suspicious => suspicious += 1,
            VerdictCategory::Dangerous => dangerous += 1,
            VerdictCategory::Unknown => unknown += 1,
        }
    }
    (safe, suspicious, dangerous, unknown)
}

//! Integration test: run the real collector against this machine's services
//! and classify them with the seeded rules. Proves the whole Fase-1 pipeline
//! works on a live Windows system (not just fixtures).

use deamonize_lib::{classifier, collector, db::Db};

#[test]
fn real_scan_produces_verdicts() {
    // Collect live services from the SCM.
    let services = collector::collect_services().expect("collector failed");
    assert!(
        services.len() > 10,
        "expected many services, got {}",
        services.len()
    );

    // Every service must have a name and display name.
    for s in &services {
        assert!(!s.name.is_empty(), "service with empty name");
        assert!(!s.display_name.is_empty(), "service `{}` missing display name", s.name);
    }

    // At least some services should have a resolvable binary + hash.
    let with_hash = services.iter().filter(|s| s.sha256.is_some()).count();
    assert!(with_hash > 0, "no service had a hashable binary");

    // Build an in-memory DB and load the curated seed.
    let db = Db::open_in_memory().expect("db open failed");
    let rules = db.list_rules().expect("list rules failed");
    assert!(
        rules.len() > 100,
        "seed should have loaded 100+ rules, got {}",
        rules.len()
    );

    // Classify every live service.
    let verdicts: Vec<_> = services.iter().map(|s| classifier::classify(s, &rules)).collect();
    let (safe, suspicious, dangerous, unknown) = classifier::summarize(&verdicts);
    println!(
        "live scan: {} services -> safe={safe} suspicious={suspicious} dangerous={dangerous} unknown={unknown}",
        services.len()
    );

    // Windows ships well-known safe services (e.g. EventLog, DcomLaunch);
    // the seed must classify at least a handful as safe.
    assert!(safe > 0, "expected some safe services on a real Windows box");

    // Every verdict must carry at least one reason (explainability).
    for v in &verdicts {
        assert!(!v.reasons.is_empty(), "verdict `{}` has no reasons", v.service);
    }
}

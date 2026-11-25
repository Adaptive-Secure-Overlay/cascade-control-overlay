#![forbid(unsafe_code)]
//! Integration smoke tests for the unified `cco` CLI binary.

use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn cco_bin() -> &'static str {
    env!("CARGO_BIN_EXE_cco")
}

#[test]
fn cli_wg_sim_analytics_bench_and_trust_admin_end_to_end() {
    // 1. wg-sim JSON (27 scenarios)
    let out = Command::new(cco_bin())
        .args(["wg-sim", "--format", "eve-json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let rows: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 27);

    // 2. analytics routes + n50 + monte-carlo
    let out = Command::new(cco_bin())
        .args(["analytics", "routes", "--n", "20", "--j", "3", "--m", "2"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let routes: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(routes["models"]["F1"]["total_routes"], "4896");
    assert_eq!(routes["models"]["F3"]["total_routes"], "6174");
    assert_eq!(routes["models"]["F4"]["total_routes"], "6516");

    let out = Command::new(cco_bin())
        .args([
            "analytics",
            "monte-carlo",
            "--model",
            "f4",
            "--n",
            "10",
            "--m",
            "2",
            "--j",
            "3",
            "--trials",
            "50000",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let mc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(mc["abs_error"].as_f64().unwrap() < 0.01);

    // 3. bench crypto smoke
    let out = Command::new(cco_bin())
        .args(["bench", "crypto", "--iters", "10"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // 4. trust-admin init-root -> keygen -> sign-registry -> verify
    let dir = TempDir::new().unwrap();
    let root_key = dir.path().join("root.key");
    let root_json = dir.path().join("root.json");
    let a_dir = dir.path().join("node-a");
    let b_dir = dir.path().join("node-b");
    let reg_json = dir.path().join("registry-v2.json");

    assert!(
        Command::new(cco_bin())
            .args([
                "trust-admin",
                "init-root",
                "--issuer-id",
                "cli-root",
                "--key-out",
                root_key.to_str().unwrap(),
                "--root-out",
                root_json.to_str().unwrap(),
                "--test-fixtures",
            ])
            .status()
            .unwrap()
            .success()
    );
    for (node, node_dir) in [("A", &a_dir), ("B", &b_dir)] {
        assert!(
            Command::new(cco_bin())
                .args([
                    "trust-admin",
                    "keygen",
                    "--node",
                    node,
                    "--directory",
                    node_dir.to_str().unwrap(),
                    "--test-fixtures",
                ])
                .status()
                .unwrap()
                .success()
        );
    }
    assert!(
        Command::new(cco_bin())
            .args([
                "trust-admin",
                "sign-registry",
                "--entries",
                a_dir.join("public-entry.json").to_str().unwrap(),
                b_dir.join("public-entry.json").to_str().unwrap(),
                "--trust-root",
                root_json.to_str().unwrap(),
                "--issuer-key",
                root_key.to_str().unwrap(),
                "--issuer-id",
                "cli-root",
                "--version",
                "1",
                "--output",
                reg_json.to_str().unwrap(),
                "--test-fixtures",
            ])
            .status()
            .unwrap()
            .success()
    );
    let verify_out = Command::new(cco_bin())
        .args([
            "trust-admin",
            "verify",
            "--registry",
            reg_json.to_str().unwrap(),
            "--trust-root",
            root_json.to_str().unwrap(),
            "--required-nodes",
            "A,B",
        ])
        .output()
        .unwrap();
    assert!(verify_out.status.success());
    let status: Value = serde_json::from_slice(&verify_out.stdout).unwrap();
    assert_eq!(status["authenticated"], true);
    assert_eq!(status["version"], 1);
}

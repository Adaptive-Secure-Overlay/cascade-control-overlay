#![forbid(unsafe_code)]
//! Verification suite matching Chapter 3 & Section 4.4 control numbers from
//! `pure_recalculate.py`, `PURE_RECALCULATION.md`, `calculate_and_prepare.py`,
//! and `peernet-calc/core.py`.

use cco_analytics::{
    DEFAULT_MONTE_CARLO_TRIALS, RouteModel, SECTION_44_MAX_DEVIATION, compromise_metrics, f_i2p,
    f1_tor, f3_no_rep, f4_graph_recurrence, f4_with_rep, n_mss, route_count, run_crypto_benchmark,
    simulate_compromise_monte_carlo, threshold_n50, uniform_entropy,
};
use num_bigint::BigUint;

#[test]
fn pure_recalculation_control_table_exact_match() {
    // Example from PURE_RECALCULATION.md: n=20, j=3 -> M1=4896, M3=6174, M4=6516
    assert_eq!(f1_tor(20, 3), BigUint::from(4896u32));
    assert_eq!(f3_no_rep(20, 3), BigUint::from(6174u32));
    assert_eq!(f4_with_rep(20, 3), BigUint::from(6516u32));
    assert_eq!(f_i2p(20, 3), BigUint::from(4896u64 * 4896u64));

    // All 6 control points (18 entropy + 18 S_ref values) from PURE_RECALCULATION.md
    let table: [(usize, usize, [f64; 3], [f64; 3]); 6] = [
        (
            20,
            3,
            [12.257388, 12.591990, 12.669771],
            [0.945364166, 0.971170698, 0.977169650],
        ),
        (
            20,
            6,
            [23.672073, 24.586343, 25.413565],
            [0.912866995, 0.948124026, 0.980024191],
        ),
        (
            20,
            10,
            [37.208320, 39.138532, 42.405275],
            [0.860919466, 0.905580359, 0.981165665],
        ),
        (
            100,
            3,
            [19.799585, 19.858925, 19.873570],
            [0.993378174, 0.996355351, 0.997090129],
        ),
        (
            100,
            6,
            [39.463188, 39.613656, 39.761640],
            [0.989966954, 0.993741557, 0.997453864],
        ),
        (
            100,
            10,
            [65.462132, 65.738760, 66.279067],
            [0.985303259, 0.989466935, 0.997599357],
        ),
    ];

    let models = [
        RouteModel::F1Tor,
        RouteModel::F3NoRep,
        RouteModel::F4WithRep,
    ];
    for (n, j, exp_h, exp_s_ref) in table {
        for (idx, model) in models.iter().enumerate() {
            let m = uniform_entropy(*model, n, j);
            assert_eq!(m.s_own_uniform, Some(1.0));
            let h = m.h_uniform_bits.unwrap();
            let s_ref = m.s_ref_uniform.unwrap();
            assert!(
                (h - exp_h[idx]).abs() < 1e-6,
                "H mismatch for {:?} ({n},{j}): got {h}, expected {}",
                model,
                exp_h[idx]
            );
            assert!(
                (s_ref - exp_s_ref[idx]).abs() < 1e-8,
                "S_ref mismatch for {:?} ({n},{j}): got {s_ref}, expected {}",
                model,
                exp_s_ref[idx]
            );
        }
    }

    // Boundary no-route cases for F1: (10, 10) and (11, 10)
    for n in [10, 11] {
        let m = uniform_entropy(RouteModel::F1Tor, n, 10);
        assert_eq!(m.total_routes, "0");
        assert!(m.h_uniform_bits.is_none());
        assert!(m.s_own_uniform.is_none());
    }

    // Large n=1000, j=10 must not overflow and produces exact BigUint string
    let large = uniform_entropy(RouteModel::F4WithRep, 1000, 10);
    assert!(large.total_routes.len() >= 30);
    assert!(large.h_uniform_bits.unwrap() > 99.0);
}

#[test]
fn f4_closed_form_matches_graph_recurrence_across_grid() {
    for n in 2..=60 {
        for j in 1..=10 {
            assert_eq!(
                f4_with_rep(n, j),
                f4_graph_recurrence(n, j),
                "F4 closed vs recurrence mismatch at n={n}, j={j}"
            );
        }
    }
}

#[test]
fn committee_risk_example_and_exact_n50_thresholds() {
    // Committee example from calculate_and_prepare.py: n=10, m=2, j=3
    // F1 = 64.29%, F3 = 55.82% (-8.46 pp), F4 = 54.27% (-10.02 pp)
    let r_f1 = compromise_metrics(RouteModel::F1Tor, 10, 2, 3)
        .compromise_prob
        .unwrap()
        * 100.0;
    let r_f3 = compromise_metrics(RouteModel::F3NoRep, 10, 2, 3)
        .compromise_prob
        .unwrap()
        * 100.0;
    let r_f4 = compromise_metrics(RouteModel::F4WithRep, 10, 2, 3)
        .compromise_prob
        .unwrap()
        * 100.0;

    assert!((r_f1 - (216.0 / 336.0) * 100.0).abs() < 1e-10);
    assert!((r_f3 - (326.0 / 584.0) * 100.0).abs() < 1e-10);
    assert!((r_f4 - (356.0 / 656.0) * 100.0).abs() < 1e-10);
    assert_eq!(format!("{r_f1:.2}"), "64.29");
    assert_eq!(format!("{r_f3:.2}"), "55.82");
    assert_eq!(format!("{r_f4:.2}"), "54.27");
    assert_eq!(format!("{:.2}", r_f1 - r_f3), "8.46");
    assert_eq!(format!("{:.2}", r_f1 - r_f4), "10.02");

    // Verify exact n50 boundary condition for F1, F3, F4 across (m, j)
    for model in [
        RouteModel::F1Tor,
        RouteModel::F3NoRep,
        RouteModel::F4WithRep,
    ] {
        for m in 1..=4 {
            for j in 2..=4 {
                let n50 = threshold_n50(model, m, j, 500).expect("n50 must exist");
                let at = compromise_metrics(model, n50, m, j)
                    .compromise_prob
                    .unwrap();
                assert!(at <= 0.5 + 1e-15);
                if n50 > m + 2 && !route_count(model, n50 - 1, j).eq(&BigUint::from(0u32)) {
                    let below = compromise_metrics(model, n50 - 1, m, j)
                        .compromise_prob
                        .unwrap();
                    assert!(below > 0.5);
                }
            }
        }
    }

    // Proposed F4 requires strictly smaller or equal n50 than baseline Tor F1
    let n50_tor = threshold_n50(RouteModel::F1Tor, 2, 3, 500).unwrap();
    let n50_f3 = threshold_n50(RouteModel::F3NoRep, 2, 3, 500).unwrap();
    let n50_f4 = threshold_n50(RouteModel::F4WithRep, 2, 3, 500).unwrap();
    assert!(n50_f4 <= n50_f3 && n50_f3 <= n50_tor);

    // MSS branch-tree combinatorics check (`peernet-calc/core.py`)
    assert!(n_mss(2, 3, 7) > BigUint::from(0u32));
}

#[test]
fn rayon_monte_carlo_800k_matches_analytics_within_section_44_bound() {
    for model in [
        RouteModel::F1Tor,
        RouteModel::F3NoRep,
        RouteModel::F4WithRep,
    ] {
        let rep = simulate_compromise_monte_carlo(
            model,
            10,
            2,
            3,
            DEFAULT_MONTE_CARLO_TRIALS,
            0xC0DE_2026_0001 + (model as u64),
        )
        .unwrap();
        assert_eq!(rep.trials, DEFAULT_MONTE_CARLO_TRIALS);
        assert!(
            rep.abs_error <= SECTION_44_MAX_DEVIATION,
            "Monte Carlo deviation too large for {:?}: empirical={} analytical={} err={}",
            model,
            rep.empirical_prob,
            rep.analytical_prob,
            rep.abs_error
        );
    }
}

#[test]
fn crypto_benchmark_smoke_x25519_and_ed25519() {
    let report = run_crypto_benchmark(20, 1, 1024, false);
    assert_eq!(report.payload_bytes, 1024);
    assert!(report.x25519_hkdf_aes128_seal_open.median_us > 0.0);
    assert!(report.x25519_hkdf_aes256_seal_open.median_us > 0.0);
    assert!(report.ed25519_sign_verify.median_us > 0.0);
}

#![forbid(unsafe_code)]
//! Analytical route combinatorics, compromise risk, `n50` thresholds,
//! multi-threaded `rayon` Monte Carlo simulation, and cryptographic benchmarks.

pub mod combinatorics;
pub mod crypto_bench;
pub mod monte_carlo;

pub use combinatorics::{
    CompromiseMetrics, EntropyMetrics, RouteModel, binomial, compromise_metrics, f_i2p, f1_tor,
    f3_no_rep, f4_graph_recurrence, f4_with_rep, falling_factorial, log2_biguint, mss_aux_a, n_mss,
    ratio_biguint_to_f64, route_count, threshold_n50, uniform_entropy,
};
pub use crypto_bench::{CryptoBenchReport, OpTiming, run_crypto_benchmark};
pub use monte_carlo::{
    DEFAULT_MONTE_CARLO_TRIALS, MonteCarloReport, SECTION_44_MAX_DEVIATION,
    simulate_compromise_monte_carlo,
};

#![forbid(unsafe_code)]
//! Multi-threaded `rayon` Monte Carlo route compromise simulator (`800,000+` routes).
//!
//! Draws mathematically uniform admissible routes for each Chapter 3 model (`F1`, `F3`, `F4`)
//! and compares the empirical interception rate against the exact analytical formula.

use std::time::Instant;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::combinatorics::{RouteModel, compromise_metrics, ratio_biguint_to_f64};

/// Default dissertation Monte Carlo trial count (`800,000` routes, Section 4.4).
pub const DEFAULT_MONTE_CARLO_TRIALS: usize = 800_000;

/// Maximum analytical-vs-empirical deviation asserted in Section 4.4 (`<= 0.004`).
pub const SECTION_44_MAX_DEVIATION: f64 = 0.004;

/// Output report produced by [`simulate_compromise_monte_carlo`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonteCarloReport {
    pub model: RouteModel,
    pub n: usize,
    pub m: usize,
    pub j: usize,
    pub trials: usize,
    pub intercepted: usize,
    pub empirical_prob: f64,
    pub analytical_prob: f64,
    pub abs_error: f64,
    pub elapsed_ms: f64,
}

/// Precomputed exact transition probabilities for uniform `F4` walks from `A = 0` to `B = 1`.
///
/// For `rem` remaining intermediate hops after choosing the next vertex:
/// - `ways_b[rem]`: number of valid walks of `rem + 1` edges from `B` to `B` without self-loops.
/// - `ways_o[rem]`: number of valid walks of `rem + 1` edges from `other != B` to `B`.
///
/// When currently at `curr != B`, probability of transitioning to `B` is
/// `ways_b[rem] / (ways_b[rem] + (n - 2) * ways_o[rem])`.
struct F4TransitionTable {
    prob_pick_b_from_other: Vec<f64>,
}

impl F4TransitionTable {
    fn new(n: usize, j: usize) -> Self {
        let mut ways_b = vec![BigUint::zero(); j + 1];
        let mut ways_o = vec![BigUint::zero(); j + 1];
        // rem = 0 means one direct edge left to B: from B -> 0 ways, from other -> 1 way.
        ways_b[0] = BigUint::zero();
        ways_o[0] = BigUint::one();

        let n_m1 = BigUint::from(n - 1);
        let n_m2 = BigUint::from(n - 2);
        for rem in 1..=j {
            ways_b[rem] = &n_m1 * &ways_o[rem - 1];
            ways_o[rem] = &ways_b[rem - 1] + &n_m2 * &ways_o[rem - 1];
        }

        let mut prob_pick_b_from_other = vec![0.0; j];
        for (step, slot) in prob_pick_b_from_other.iter_mut().enumerate() {
            let rem = j - 1 - step;
            let num = &ways_b[rem];
            let den = num + &n_m2 * &ways_o[rem];
            *slot = ratio_biguint_to_f64(num, &den).unwrap_or(0.0);
        }
        Self {
            prob_pick_b_from_other,
        }
    }
}

/// Runs a multi-threaded `rayon` Monte Carlo simulation of `trials` uniformly random routes.
///
/// Compromised set is `{2, 3, ..., 2 + m - 1}` while trusted endpoints are `A = 0` and `B = 1`.
#[must_use]
pub fn simulate_compromise_monte_carlo(
    model: RouteModel,
    n: usize,
    m: usize,
    j: usize,
    trials: usize,
    seed: u64,
) -> Option<MonteCarloReport> {
    let analytical = compromise_metrics(model, n, m, j);
    let analytical_prob = analytical.compromise_prob?;
    if trials == 0 {
        return None;
    }

    let start = Instant::now();
    let f4_table = (model == RouteModel::F4WithRep).then(|| F4TransitionTable::new(n, j));

    let chunk_size = 10_000usize;
    let num_chunks = trials.div_ceil(chunk_size);
    let intercepted: usize = (0..num_chunks)
        .into_par_iter()
        .map(|chunk_idx| {
            let count = if (chunk_idx + 1) * chunk_size > trials {
                trials - chunk_idx * chunk_size
            } else {
                chunk_size
            };
            let mut rng = SmallRng::seed_from_u64(
                seed.wrapping_add((chunk_idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)),
            );
            let mut hits = 0usize;
            let mut pool: Vec<usize> = match model {
                RouteModel::F1Tor => (2..n).collect(),
                RouteModel::F3NoRep => (0..n).collect(),
                RouteModel::F4WithRep => Vec::new(),
            };

            match model {
                RouteModel::F1Tor => {
                    for _ in 0..count {
                        if sample_f1_hit(&mut rng, &mut pool, j, m) {
                            hits += 1;
                        }
                    }
                }
                RouteModel::F3NoRep => {
                    for _ in 0..count {
                        if sample_f3_hit(&mut rng, &mut pool, j, m) {
                            hits += 1;
                        }
                    }
                }
                RouteModel::F4WithRep => {
                    let table = f4_table.as_ref().unwrap();
                    for _ in 0..count {
                        if sample_f4_hit(&mut rng, n, j, m, table) {
                            hits += 1;
                        }
                    }
                }
            }
            hits
        })
        .sum();

    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let empirical_prob = (intercepted as f64) / (trials as f64);
    let abs_error = (empirical_prob - analytical_prob).abs();

    Some(MonteCarloReport {
        model,
        n,
        m,
        j,
        trials,
        intercepted,
        empirical_prob,
        analytical_prob,
        abs_error,
        elapsed_ms,
    })
}

#[inline]
fn sample_f1_hit(rng: &mut SmallRng, pool: &mut [usize], j: usize, m: usize) -> bool {
    let len = pool.len();
    let limit = 2 + m;
    let mut hit = false;
    for i in 0..j {
        let pick = rng.gen_range(i..len);
        pool.swap(i, pick);
        if pool[i] < limit {
            hit = true;
        }
    }
    hit
}

#[inline]
fn sample_f3_hit(rng: &mut SmallRng, pool: &mut [usize], j: usize, m: usize) -> bool {
    let len = pool.len();
    let limit = 2 + m;
    loop {
        for i in 0..j {
            let pick = rng.gen_range(i..len);
            pool.swap(i, pick);
        }
        // Admissible F3 route: first relay != A (0), last relay != B (1)
        if pool[0] != 0 && pool[j - 1] != 1 {
            return pool[..j].iter().any(|&node| node >= 2 && node < limit);
        }
    }
}

#[inline]
fn sample_f4_hit(
    rng: &mut SmallRng,
    n: usize,
    j: usize,
    m: usize,
    table: &F4TransitionTable,
) -> bool {
    let mut curr = 0usize; // Start at A = 0
    let mut hit = false;
    let limit = 2 + m;

    for &p_b in table.prob_pick_b_from_other.iter().take(j) {
        let next = if curr == 1 {
            // Currently at B: pick uniformly among all n - 1 nodes != B
            let r = rng.gen_range(0..(n - 1));
            if r == 0 { 0 } else { r + 1 }
        } else if p_b > 0.0 && rng.r#gen::<f64>() < p_b {
            1 // Transition to B
        } else {
            // Pick uniformly among the (n - 2) nodes excluding `curr` and `B = 1`
            let r = rng.gen_range(0..(n - 2));
            // Map 0..(n-2) onto {0..n} \ {1, curr}
            let mut candidate = if r == 0 { 0 } else { r + 1 };
            if curr == 0 {
                // Excluded {0, 1} -> remaining are {2..n}
                candidate = r + 2;
            } else if candidate >= curr {
                candidate += 1;
            }
            candidate
        };
        if next >= 2 && next < limit {
            hit = true;
        }
        curr = next;
    }
    hit
}

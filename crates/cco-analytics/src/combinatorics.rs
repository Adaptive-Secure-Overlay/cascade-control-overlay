#![forbid(unsafe_code)]
//! Exact route combinatorics, Shannon entropy, compromise risk, and `n50` threshold
//! calculations from Chapter 3 of the dissertation (`pure_recalculate.py`, `peernet-calc/core.py`).
//!
//! Uses arbitrary-precision integers (`BigInt`/`BigUint`) so calculations remain exact even
//! at `n = 1000, j = 10` (`> 10^30` routes) without overflow.

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, ToPrimitive, Zero};
use serde::{Deserialize, Serialize};

/// Route space model studied in Chapter 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RouteModel {
    /// Baseline Tor-like model (`F1`): endpoints A and B excluded from intermediate hops, no repeats.
    #[serde(rename = "F1")]
    F1Tor,
    /// Proposed cascade model without repeats (`F3` / `M1`): A and B may participate as relays
    /// (first hop != A, last hop != B), all intermediate hops distinct.
    #[serde(rename = "F3")]
    F3NoRep,
    /// Proposed cascade model with repeats (`F4` / `M2`): relays may repeat non-consecutively,
    /// self-transitions (`u -> u`) are forbidden.
    #[serde(rename = "F4")]
    F4WithRep,
}

impl RouteModel {
    /// Short model code matching Chapter 3 notation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::F1Tor => "F1",
            Self::F3NoRep => "F3",
            Self::F4WithRep => "F4",
        }
    }
}

/// Computes the falling factorial `(x)_k = x * (x - 1) * ... * (x - k + 1)` exactly.
///
/// Returns `0` when `k > x`.
#[must_use]
pub fn falling_factorial(x: usize, k: usize) -> BigUint {
    if k == 0 {
        return BigUint::one();
    }
    if k > x {
        return BigUint::zero();
    }
    let mut acc = BigUint::one();
    for i in 0..k {
        acc *= BigUint::from(x - i);
    }
    acc
}

/// Exact binomial coefficient `C(n, k)`.
#[must_use]
pub fn binomial(n: usize, k: usize) -> BigUint {
    if k > n {
        return BigUint::zero();
    }
    let k = k.min(n - k);
    let mut num = BigUint::one();
    let mut den = BigUint::one();
    for i in 0..k {
        num *= BigUint::from(n - i);
        den *= BigUint::from(i + 1);
    }
    num / den
}

/// Baseline Tor route space `F1(n, j) = (n - 2)_j`.
#[must_use]
pub fn f1_tor(n: usize, j: usize) -> BigUint {
    if n < 2 || j > n - 2 {
        return BigUint::zero();
    }
    falling_factorial(n - 2, j)
}

/// Baseline I2P route space `F_I2P(n, j) = F_Tor(n, j)^2` (inbound + outbound tunnel).
#[must_use]
pub fn f_i2p(n: usize, j: usize) -> BigUint {
    let tor = f1_tor(n, j);
    &tor * &tor
}

/// Proposed model without repeats `F3(n, j)` (also `M1` / `f1_no_rep`).
///
/// Closed form by inclusion-exclusion:
/// - `j == 1`: `n - 2` (for `n >= 2`)
/// - `2 <= j <= n`: `(n)_j - 2*(n - 1)_{j - 1} + (n - 2)_{j - 2}`
#[must_use]
pub fn f3_no_rep(n: usize, j: usize) -> BigUint {
    if n < 2 || j == 0 || j > n {
        return BigUint::zero();
    }
    if j == 1 {
        return BigUint::from(n - 2);
    }
    let term1 = BigInt::from(falling_factorial(n, j));
    let term2 = BigInt::from(2u32) * BigInt::from(falling_factorial(n - 1, j - 1));
    let term3 = BigInt::from(falling_factorial(n - 2, j - 2));
    let res = term1 - term2 + term3;
    if res.is_negative() {
        BigUint::zero()
    } else {
        res.to_biguint().unwrap_or_default()
    }
}

/// Proposed model with non-consecutive repeats `F4(n, j)` (also `M2` / `f2_rep`).
///
/// Exact closed form: `M4(n, j) = ((n - 1)^(j + 1) - (-1)^(j + 1)) / n`.
#[must_use]
pub fn f4_with_rep(n: usize, j: usize) -> BigUint {
    if n < 2 || j == 0 {
        return BigUint::zero();
    }
    let exp = (j + 1) as u32;
    let base = BigInt::from(n - 1);
    let power = base.pow(exp);
    let sign = if exp % 2 == 0 {
        BigInt::one()
    } else {
        -BigInt::one()
    };
    let num = power - sign;
    let den = BigInt::from(n);
    let q = num / den;
    if q.is_negative() {
        BigUint::zero()
    } else {
        q.to_biguint().unwrap_or_default()
    }
}

/// Independent graph-recurrence verifier for `F4(n, j)` (`pure_recalculate.py`).
#[must_use]
pub fn f4_graph_recurrence(n: usize, j: usize) -> BigUint {
    if n < 2 || j == 0 {
        return BigUint::zero();
    }
    let mut at_b = BigUint::zero();
    let mut elsewhere = BigUint::one();
    let n_minus_1 = BigUint::from(n - 1);
    let n_minus_2 = BigUint::from(n - 2);
    for _ in 0..=j {
        let next_at_b = elsewhere.clone();
        let next_elsewhere = &n_minus_1 * &at_b + &n_minus_2 * &elsewhere;
        at_b = next_at_b;
        elsewhere = next_elsewhere;
    }
    at_b
}

/// Dispatches exact route count calculation for a given [`RouteModel`].
#[must_use]
pub fn route_count(model: RouteModel, n: usize, j: usize) -> BigUint {
    match model {
        RouteModel::F1Tor => f1_tor(n, j),
        RouteModel::F3NoRep => f3_no_rep(n, j),
        RouteModel::F4WithRep => f4_with_rep(n, j),
    }
}

/// High-accuracy `log2(x)` for arbitrary-precision positive [`BigUint`].
///
/// Extracts the top 53 bits of the integer into an IEEE-754 mantissa and adds the bit shift,
/// achieving `< 1e-14` bit error even for 200+ bit route counts.
#[must_use]
pub fn log2_biguint(x: &BigUint) -> Option<f64> {
    if x.is_zero() {
        return None;
    }
    let bits = x.bits();
    if bits <= 53 {
        return x.to_f64().map(f64::log2);
    }
    let shift = bits - 53;
    let top: u64 = (x >> shift).to_u64()?;
    let remainder_bit = if shift > 0 {
        let half = (x >> (shift - 1)).bit(0);
        u64::from(half)
    } else {
        0
    };
    let scaled = (top as f64) + 0.5 * (remainder_bit as f64);
    Some(scaled.log2() + shift as f64)
}

/// Converts a ratio `num / den` of two `BigUint`s into `f64` without overflow.
#[must_use]
pub fn ratio_biguint_to_f64(num: &BigUint, den: &BigUint) -> Option<f64> {
    if den.is_zero() {
        return None;
    }
    if num.is_zero() {
        return Some(0.0);
    }
    let max_bits = num.bits().max(den.bits());
    if max_bits <= 1000 {
        if let (Some(nf), Some(df)) = (num.to_f64(), den.to_f64()) {
            if nf.is_finite() && df.is_finite() && df > 0.0 {
                return Some(nf / df);
            }
        }
    }
    let shift = max_bits.saturating_sub(64);
    let nf = (num >> shift).to_f64()?;
    let df = (den >> shift).to_f64()?;
    if df > 0.0 { Some(nf / df) } else { None }
}

/// Exact uniform-choice Shannon entropy report (`pure_recalculate.py`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntropyMetrics {
    pub model: RouteModel,
    pub n: usize,
    pub j: usize,
    pub total_routes: String,
    pub h_uniform_bits: Option<f64>,
    pub s_own_uniform: Option<f64>,
    pub s_ref_uniform: Option<f64>,
}

/// Computes uniform-assumption route entropy metrics for `(model, n, j)`.
#[must_use]
pub fn uniform_entropy(model: RouteModel, n: usize, j: usize) -> EntropyMetrics {
    let count = route_count(model, n, j);
    if count.is_zero() {
        return EntropyMetrics {
            model,
            n,
            j,
            total_routes: "0".to_owned(),
            h_uniform_bits: None,
            s_own_uniform: None,
            s_ref_uniform: None,
        };
    }
    let h = log2_biguint(&count).unwrap_or(0.0);
    let s_own = if count > BigUint::one() {
        Some(1.0)
    } else {
        None
    };
    let s_ref = if j > 0 && n > 1 {
        Some(h / ((j as f64) * (n as f64).log2()))
    } else {
        None
    };
    EntropyMetrics {
        model,
        n,
        j,
        total_routes: count.to_string(),
        h_uniform_bits: Some(h),
        s_own_uniform: s_own,
        s_ref_uniform: s_ref,
    }
}

/// Exact compromise risk analysis for a given `(model, n, m, j)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompromiseMetrics {
    pub model: RouteModel,
    pub n: usize,
    pub m: usize,
    pub j: usize,
    pub total_routes: String,
    pub safe_routes: String,
    pub compromised_routes: String,
    pub compromise_prob: Option<f64>,
    pub success_prob: Option<f64>,
}

/// Computes exact route compromise probability `P_risk = 1 - F(n - m, j) / F(n, j)`
/// when `m` out of `n - 2` intermediate nodes are controlled by an adversary.
#[must_use]
pub fn compromise_metrics(model: RouteModel, n: usize, m: usize, j: usize) -> CompromiseMetrics {
    let total = route_count(model, n, j);
    if total.is_zero() || m + 2 > n {
        return CompromiseMetrics {
            model,
            n,
            m,
            j,
            total_routes: total.to_string(),
            safe_routes: "0".to_owned(),
            compromised_routes: total.to_string(),
            compromise_prob: None,
            success_prob: None,
        };
    }
    let safe = if m == 0 {
        total.clone()
    } else {
        route_count(model, n - m, j)
    };
    let compromised = if total >= safe {
        &total - &safe
    } else {
        BigUint::zero()
    };
    let risk = ratio_biguint_to_f64(&compromised, &total);
    let success = risk.map(|r| 1.0 - r);
    CompromiseMetrics {
        model,
        n,
        m,
        j,
        total_routes: total.to_string(),
        safe_routes: safe.to_string(),
        compromised_routes: compromised.to_string(),
        compromise_prob: risk,
        success_prob: success,
    }
}

/// Exact integer search for threshold `n50`: the smallest network size `n >= max(m + 2, 3)`
/// such that `F(n, j) > 0` and compromise probability `<= 1/2` (i.e. `2 * F(n - m, j) >= F(n, j)`).
#[must_use]
pub fn threshold_n50(model: RouteModel, m: usize, j: usize, max_n: usize) -> Option<usize> {
    let start = (m + 2).max(3);
    for n in start..=max_n {
        let total = route_count(model, n, j);
        if total.is_zero() {
            continue;
        }
        let safe = route_count(model, n - m, j);
        if (&safe * 2u32) >= total {
            return Some(n);
        }
    }
    None
}

/// Auxiliary recurrence `A(j, k, n)` for MCC cascade combinatorics (`peernet-calc/core.py`).
#[must_use]
pub fn mss_aux_a(j: usize, k: usize, n: usize) -> BigUint {
    if j == 0 {
        return BigUint::zero();
    }
    if j == 1 {
        return BigUint::one();
    }
    let mut dp = vec![BigUint::zero(); j + 1];
    dp[1] = BigUint::one();
    if j >= 2 {
        let c1 = if n >= 1 {
            binomial(n - 1, k)
        } else {
            BigUint::zero()
        };
        let c2 = if n >= 2 {
            binomial(n - 2, k)
        } else {
            BigUint::zero()
        };
        dp[2] = c1 + c2;
    }
    let c_n2_km1 = if n >= 2 && k >= 1 {
        binomial(n - 2, k - 1)
    } else {
        BigUint::zero()
    };
    let c_n1_k = if n >= 1 {
        binomial(n - 1, k)
    } else {
        BigUint::zero()
    };
    let c_n2_k = if n >= 2 {
        binomial(n - 2, k)
    } else {
        BigUint::zero()
    };
    let pair_coeff = &c_n2_km1 * &c_n1_k;
    for step in 3..=j {
        dp[step] = &pair_coeff * &dp[step - 2] + &c_n2_k * &dp[step - 1];
    }
    dp[j].clone()
}

/// Exact MCC branch-tree count `N_MSS(j, k, n)` (`peernet-calc/core.py`, formula 7).
#[must_use]
pub fn n_mss(j: usize, k: usize, n: usize) -> BigUint {
    if j == 0 || k == 0 || n < 2 {
        return BigUint::zero();
    }
    if j == 1 {
        return binomial(n - 2, k - 1);
    }
    let mut prev = binomial(n - 2, k - 1);
    for step in 2..=j {
        let a_prev = mss_aux_a(step - 1, k, n);
        if a_prev.is_zero() {
            return BigUint::zero();
        }
        let a_curr = mss_aux_a(step, k, n);
        prev = prev.pow(k as u32) / a_prev * a_curr;
    }
    prev
}

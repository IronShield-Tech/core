//! JavaScript/WASM bindings for IronShield proof-of-work solving

#[cfg(any(feature = "wasm", rust_analyzer))]
use wasm_bindgen::prelude::*;

#[cfg(any(feature = "wasm", rust_analyzer))]
use hex;

#[cfg(any(feature = "wasm", rust_analyzer))]
use serde_json;


use crate::*;

/// Outputs debug message to browser console.
///
/// # Arguments
/// * `s`: Message string to log.
///
/// # Note
/// Useful for debugging WASM execution from JavaScript.
#[cfg(any(feature = "wasm", rust_analyzer))]
#[wasm_bindgen]
pub fn console_log(s: &str) {
    web_sys::console::log_1(&JsValue::from_str(s));
}

/// JavaScript-compatible solution result for IronShield challenges
///
/// * `solution_str`:            String representation of the solution nonce
///                              to avoid JavaScript BigInt precision issues.
/// * `solution`:                Original numeric value for compatibility.
/// * `challenge_signature_hex`: Challenge signature preserved from the 
///                              original challenge.
#[cfg(any(feature = "wasm", rust_analyzer))]
#[derive(serde::Serialize)]
struct IronShieldSolutionResult {
    solution_str:            String,
    solution:                i64,
    challenge_signature_hex: String,
}

/// Creates a standardized IronShield solution result from core library output.
#[cfg(any(feature = "wasm", rust_analyzer))]
fn create_ironshield_solution_result(response: IronShieldChallengeResponse) -> IronShieldSolutionResult {
    IronShieldSolutionResult {
        solution_str: response.solution.to_string(),
        solution: response.solution,
        challenge_signature_hex: hex::encode(response.solved_challenge.challenge_signature),
    }
}

/// Solves IronShield proof-of-work challenges using optimized multithreaded computation.
///
/// This function provides the fastest possible PoW solving by distributing the work
/// across the specified number of threads with optimal load balancing and early termination.
///
/// # Arguments
/// * `challenge_json`: JSON string containing the IronShieldChallenge
/// * `num_threads`:    Number of threads to use (optional, defaults to available cores)
/// * `start_offset`:   Starting nonce offset for worker coordination (optional)
/// * `stride`:         Nonce increment stride for worker coordination (optional) 
///
/// # Returns
/// JavaScript object with solution nonce and challenge signature, or error message.
///
/// # Performance
/// - **Multi-core scaling**:      Near-linear performance improvement with thread count.
/// - **Thread-stride algorithm**: Optimal load balancing without coordination overhead.
/// - **Early termination**:       Stops all threads immediately when a solution is found.
/// - **Memory efficient**:        Minimal overhead compared to a single-threaded version.
#[cfg(all(any(feature = "wasm", rust_analyzer), any(feature = "threading", rust_analyzer)))]
#[wasm_bindgen]
pub fn solve_ironshield_challenge_multi_threaded(
    challenge_json: &str,
    start_offset: Option<u32>,
    stride: Option<u32>,
    progress_callback: &js_sys::Function,
) -> Result<JsValue, JsValue> {
    // Skip panic hook installation to avoid "unreachable executed" in workers
    // console_error_panic_hook::set_once()

    console_log("🚀 [WASM] solve_ironshield_challenge_multi_threaded() called - using WORKER COORDINATION algorithm");

    // Parse the challenge JSON
    let challenge: IronShieldChallenge = serde_json::from_str(challenge_json)
        .map_err(|e: serde_json::Error| JsValue::from_str(&format!("Error parsing challenge JSON: {}", e)))?;

    let start: Option<usize> = start_offset.map(|n: u32| n as usize);
    let step: Option<usize> = stride.map(|n: u32| n as usize);
    
    if let (Some(start_val), Some(stride_val)) = (start, step) {
        console_log(&format!("🎯 [WASM] JavaScript worker coordination: start={}, stride={} (checks nonce's {}, {}, {}, ...)", start_val, stride_val, start_val, start_val + stride_val, start_val + 2*stride_val));
    } else {
        console_log("🔄 [WASM] Single-threaded fallback mode (no worker coordination)");
    }

    // Create a Rust closure that wraps the JavaScript callback function
    let callback: js_sys::Function = progress_callback.clone();
    let closure = move |progress: u64| {
        // Call the JavaScript function, passing the progress value
        let _ = callback.call1(&JsValue::NULL, &JsValue::from(progress));
    };

    // Find valid nonce using JavaScript worker coordinated algorithm.
    let response: IronShieldChallengeResponse = find_solution(
        &challenge,
        Some(PoWConfig::multi_threaded()),
        start, 
        step,
        Some(&closure)
    ).map_err(|e: String| JsValue::from_str(&format!("Error solving IronShield challenge with worker coordination: {}", e)))?;

    console_log("✅ [WASM] Worker coordination solution found");

    // Convert the response to a JavaScript object
    let result: js_sys::Object = js_sys::Object::new();
    js_sys::Reflect::set(&result, &"solution_str".into(), &response.solution.to_string().into())?;
    js_sys::Reflect::set(&result, &"solution".into(), &JsValue::from(response.solution))?;
    js_sys::Reflect::set(&result, &"challenge_signature_hex".into(), &hex::encode(response.solved_challenge.challenge_signature).into())?;

    Ok(result.into())
}

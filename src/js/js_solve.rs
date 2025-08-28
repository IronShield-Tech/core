//! JavaScript/WASM bindings for IronShield proof-of-work solving

#[cfg(any(feature = "wasm", rust_analyzer))]
use wasm_bindgen::prelude::*;

#[cfg(any(feature = "wasm", rust_analyzer))]
use serde_wasm_bindgen;

#[cfg(any(feature = "wasm", rust_analyzer))]
use crate::*;

/// JavaScript-compatible wrapper for `PoWConfig`
/// with JSON serialization.
#[cfg(any(feature = "wasm", rust_analyzer))]
#[wasm_bindgen]
pub struct JsPoWConfig {
    inner: PoWConfig,
}

#[cfg(any(feature = "wasm", rust_analyzer))]
#[wasm_bindgen]
impl JsPoWConfig {
    /// Creates a default PoW configuration.
    /// 
    /// This is equivalent to `single_threaded()` and uses conservative limits
    /// suitable for single-threaded execution.
    /// 
    /// # Returns
    /// * `JsPoWConfig`: Default configuration optimized for single-threaded proof-of-work
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: PoWConfig::default(),
        }
    }

    /// Creates a single-threaded PoW configuration.
    /// 
    /// Uses conservative limits suitable for single-threaded execution.
    /// 
    /// # Returns
    /// * `JsPoWConfig`: Configuration optimized for single-threaded proof-of-work
    #[wasm_bindgen]
    pub fn single_threaded() -> Self {
        Self {
            inner: PoWConfig::single_threaded(),
        }
    }

    /// Creates a multi-threaded PoW configuration.
    /// 
    /// Uses higher limits suitable for coordinated multi-threaded execution.
    /// 
    /// # Returns
    /// * `JsPoWConfig`: Configuration optimized for multi-threaded proof-of-work
    #[wasm_bindgen]
    pub fn multi_threaded() -> Self {
        Self {
            inner: PoWConfig::multi_threaded(),
        }
    }

    /// Creates a custom PoW configuration with specified parameters.
    /// 
    /// # Arguments
    /// * `max_attempts`: Maximum number of nonces to try before giving up
    /// * `progress_reporting_interval`: How often to report progress (in attempts)
    /// 
    /// # Returns
    /// * `JsPoWConfig`: Custom configuration with specified parameters
    #[wasm_bindgen]
    pub fn custom(max_attempts: i64, progress_reporting_interval: u64) -> Self {
        Self {
            inner: PoWConfig::custom(max_attempts, progress_reporting_interval),
        }
    }

    /// Gets the maximum number of attempts before giving up.
    /// 
    /// # Returns
    /// * `i64`: Maximum attempts
    #[wasm_bindgen(getter)]
    pub fn max_attempts(&self) -> i64 {
        self.inner.max_attempts
    }

    /// Gets the progress reporting interval.
    /// 
    /// # Returns
    /// * `u64`: Progress reporting interval in attempts
    #[wasm_bindgen(getter)]
    pub fn progress_reporting_interval(&self) -> u64 {
        self.inner.progress_reporting_interval
    }

    /// Creates a PoW configuration from a JSON string.
    /// 
    /// # Arguments
    /// * `json_str`: JSON representation of the PoW configuration.
    /// 
    /// # Returns
    /// * `Result<JsPoWConfig, JsValue>`: A wrapped configuration or an error if parsing fails.
    #[wasm_bindgen]
    pub fn from_json(json_str: &str) -> Result<Self, JsValue> {
        let config: PoWConfig = serde_json::from_str(json_str)
            .map_err(|e: serde_json::Error| JsValue::from_str(&format!("Failed to parse JSON: {}", e)))?;

        Ok(JsPoWConfig { inner: config })
    }

    /// Converts the PoW configuration to a JSON string.
    /// 
    /// # Returns
    /// * `Result<String, JsValue>`: A JSON string representation of the configuration
    ///                              or an error if serialization fails.
    #[wasm_bindgen]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e: serde_json::Error| JsValue::from_str(&format!("Failed to serialize PoW configuration to JSON: {}", e)))
    }

    /// Converts the configuration to a JavaScript object.
    /// 
    /// # Returns
    /// * `Result<JsValue, JsValue>`: JavaScript object or error
    ///                               if serialization fails.
    #[wasm_bindgen]
    pub fn to_js_object(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.inner)
            .map_err(|e: serde_wasm_bindgen::Error| JsValue::from_str(&format!("Failed to convert PoW configuration to JS object: {:?}", e)))
    }
}

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

/// Solves IronShield proof-of-work challenges using the core find_solution function.
///
/// This is the main solving function that handles both single-threaded and worker coordination modes.
///
/// # Arguments
/// * `challenge_json`: JSON string containing the IronShieldChallenge
/// * `config_json`: Optional JSON string containing PoWConfig (null for default multi-threaded config)
/// * `start_offset`: Optional starting nonce offset for worker coordination 
/// * `stride`: Optional nonce increment stride for worker coordination
/// * `progress_callback`: Optional JavaScript function for progress reporting
///
/// # Returns
/// JavaScript object containing the IronShieldChallengeResponse or error message.
#[cfg(any(feature = "wasm", rust_analyzer))]
#[wasm_bindgen]
pub fn find_solution(
    challenge_json: &str,
    config_json: Option<String>,
    start_offset: Option<u32>,
    stride: Option<u32>,
    progress_callback: Option<js_sys::Function>,
) -> Result<JsValue, JsValue> {
    // Parse the challenge from the JSON string
    let challenge: IronShieldChallenge = serde_json::from_str(challenge_json)
        .map_err(|e: serde_json::Error| JsValue::from_str(&format!("Error parsing challenge JSON: {}", e)))?;

    // Parse the PoWConfig from the JSON string
    let config: Option<PoWConfig> = if let Some(config_str) = config_json {
        let parsed_config: PoWConfig = serde_json::from_str(&config_str)
            .map_err(|e: serde_json::Error| JsValue::from_str(&format!("Error parsing config JSON: {}", e)))?;
        Some(parsed_config)
    } else {
        None
    };

    // Convert start_offset and stride to usize
    let start: Option<usize> = start_offset.map(|n: u32| n as usize);
    let step: Option<usize> = stride.map(|n: u32| n as usize);

    // Create progress callback closure if provided with proper type conversions
    let callback_closure: Option<Box<dyn Fn(u64)>> = if let Some(callback) = progress_callback {
        Some(Box::new(move |progress: u64| {
            let _ = callback.call1(&JsValue::NULL, &JsValue::from(progress));
        }))
    } else {
        None
    };

    // Call the core find_solution function
    let response: IronShieldChallengeResponse = crate::solve::find_solution(
        &challenge,
        config,
        start,
        step,
        callback_closure.as_ref().map(|cb: &Box<dyn Fn(u64)>| cb.as_ref())
    ).map_err(|e: String| JsValue::from_str(&format!("Error solving challenge: {}", e)))?;

    // Return the IronShieldChallengeResponse directly 
    serde_wasm_bindgen::to_value(&response)
        .map_err(|e| JsValue::from_str(&format!("Error serializing response: {:?}", e)))
}

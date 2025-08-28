//! JavaScript/WASM bindings for IronShield types

#[cfg(any(feature = "wasm", rust_analyzer))]
pub mod js_solve;

#[cfg(any(feature = "wasm", rust_analyzer))]
pub mod js_verify;


#[cfg(any(feature = "wasm", rust_analyzer))]
pub use js_solve::*;

#[cfg(any(feature = "wasm", rust_analyzer))]
pub use js_verify::*;



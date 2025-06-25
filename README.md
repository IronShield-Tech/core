# IronShield Core

Core proof-of-work solving and verification library for the IronShield system.

[![Crates.io](https://img.shields.io/crates/v/ironshield-core.svg)](https://crates.io/crates/ironshield-core)
[![Documentation](https://docs.rs/ironshield-core/badge.svg)](https://docs.rs/ironshield-core)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)

## Overview

`ironshield-core` provides high-performance proof-of-work solving and verification algorithms for the IronShield DDoS protection system. It includes both single-threaded and parallel implementations optimized for different deployment environments.

## Features

- **PoW Solving**: Efficient nonce-finding algorithms with configurable difficulty
- **Parallel Processing**: Multi-threaded solving using Rayon (optional)
- **Challenge Verification**: Validate PoW solutions against challenge parameters
- **Performance Optimized**: Optimized for both WASM and native environments
- **Flexible Difficulty**: Support for both legacy and modern difficulty systems

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ironshield-core = "0.1.0"
```

For single-threaded environments (like WASM), disable parallel features:

```toml
[dependencies]
ironshield-core = { version = "0.1.0", default-features = false }
```

## Quick Start

### Basic PoW Solving

```rust
use ironshield_core::*;
use ironshield_types::*;

// Legacy string-based challenge
let challenge = "example_challenge_string";
let difficulty = 4; // number of leading zeros required

match find_solution(challenge, difficulty) {
    Ok((nonce, hash)) => {
        println!("Found solution! Nonce: {}, Hash: {}", nonce, hash);
    }
    Err(e) => println!("No solution found: {}", e),
}
```

### Modern IronShield Challenge Solving

```rust
use ironshield_core::*;
use ironshield_types::*;

// Create or receive an IronShield challenge
let challenge = IronShieldChallenge::new(/* parameters */);

// Single-threaded solving (WASM-compatible)
match find_solution_single_threaded(&challenge) {
    Ok(response) => {
        println!("Solution found: {}", response.solution);
    }
    Err(e) => println!("Failed to solve: {}", e),
}

// Multi-threaded solving (native environments)
#[cfg(feature = "parallel")]
match find_solution_multi_threaded(&challenge) {
    Ok(response) => {
        println!("Solution found: {}", response.solution);
    }
    Err(e) => println!("Failed to solve: {}", e),
}
```

### Solution Verification

```rust
use ironshield_core::*;

// Verify a legacy solution
let is_valid = verify_solution("challenge", "12345", 4);
println!("Solution valid: {}", is_valid);

// Verify an IronShield solution
let challenge = /* your challenge */;
let response = /* received response */;
match verify_ironshield_solution(&challenge, &response) {
    Ok(()) => println!("Valid solution!"),
    Err(e) => println!("Invalid solution: {}", e),
}
```

## Performance Features

### Parallel Processing

When the `parallel` feature is enabled (default), the library uses Rayon for multi-threaded solving:

```rust
// Automatically uses all available CPU cores
let response = find_solution_multi_threaded(&challenge)?;
```

### Single-threaded Mode

For WASM or single-threaded environments:

```rust
// Optimized for single-core performance
let response = find_solution_single_threaded(&challenge)?;
```

### Performance Tuning

The library includes optimized constants for different scenarios:

- **Chunk sizes** optimized for cache locality
- **Attempt limits** to prevent infinite loops
- **Hash computation** optimized for both native and WASM

## Feature Flags

- `parallel` (default): Enable multi-threaded solving with Rayon
- `no-parallel`: Explicitly disable parallel features for testing

## Algorithm Details

### Hash-based PoW

The core algorithm computes SHA-256 hashes of the format:
```
challenge_data:nonce
```

And searches for hashes that meet the difficulty threshold.

### Difficulty Systems

Supports both:
- **Legacy**: Number of leading zero bits
- **Modern**: Threshold comparison against challenge parameters

## WASM Compatibility

The library is fully compatible with WebAssembly when compiled without the `parallel` feature:

```bash
wasm-pack build --target web --no-default-features
```

## License

This project is licensed under the [Business Source License 1.1](LICENSE). 
It will automatically convert to Apache-2.0 on July 24, 2028.

## Contributing

See the main [IronShield repository](https://github.com/IronShield-Tech/IronShield) for contribution guidelines. 
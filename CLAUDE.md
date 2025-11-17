# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**binius64-eas** is a Rust project currently in early development stage.

## Development Commands

### Building
```bash
cargo build          # Debug build
cargo build --release  # Release build
```

### Running
```bash
cargo run            # Run the main binary
cargo run --release  # Run optimized binary
```

### Testing
```bash
cargo test           # Run all tests
cargo test <test_name>  # Run specific test
cargo test -- --nocapture  # Show println! output in tests
```

### Code Quality
```bash
cargo fmt            # Format code
cargo clippy         # Run linter
cargo check          # Fast compilation check without codegen
```

## Toolchain

This project uses Rust 1.91.1 as specified in `rust-toolchain.toml`. The toolchain will be automatically installed when you run any cargo command.

## Project Structure

- `src/main.rs` - Main entry point
- `Cargo.toml` - Project manifest and dependencies

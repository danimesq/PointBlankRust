//! Binary protocol primitives shared by the Point Blank client and server.
//!
//! This crate intentionally deals in bytes and wire-compatible field layouts.
//! Game rules, transports, persistence, and rendering belong in higher-level crates.

pub mod bitwise;
pub mod cmess;
pub mod framing;
pub mod packet;

//! Constraint IR, witness layout, and the reference field.
//!
//! This crate is the boundary between VM semantics and the proof engine. It
//! deliberately contains no sum-check or commitment code: relations are
//! expressed here, then reduced elsewhere.

pub mod field;
pub mod ir;
pub mod layout;
pub mod simd;

pub use field::{Field, F2, F2_128, F61};
pub use ir::{
    Constraint, ConstraintError, ConstraintSystem, EvalError, Expr, LinearCombination,
    LinearizationError, VarId, Witness,
};
pub use layout::{
    LayoutError, MemoryKind, ProjectionKind, RoutingKind, Segment, SegmentKind, SegmentOwner,
    WitnessLayout,
};
pub use simd::{DualSimdR1cs, SimdError, SimdR1cs};

//! Constraint IR, witness layout, and the reference field.
//!
//! This crate is the boundary between VM semantics and the proof engine. It
//! deliberately contains no sum-check or commitment code: relations are
//! expressed here, then reduced elsewhere.

pub mod field;
pub mod ir;
pub mod layout;

pub use field::{Field, F61};
pub use ir::{Constraint, ConstraintError, ConstraintSystem, EvalError, Expr, VarId, Witness};
pub use layout::{
    LayoutError, MemoryKind, RoutingKind, Segment, SegmentKind, SegmentOwner, WitnessLayout,
};

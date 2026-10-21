use crate::field::F2_128;
use thiserror::Error;

pub type VarId = usize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Const(F2_128),
    Var(VarId),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
}

#[allow(clippy::should_implement_trait)]
impl Expr {
    pub fn var(id: VarId) -> Self {
        Self::Var(id)
    }

    pub fn constant(value: impl Into<F2_128>) -> Self {
        Self::Const(value.into())
    }

    pub fn add(self, other: Self) -> Self {
        Self::Add(Box::new(self), Box::new(other))
    }

    pub fn sub(self, other: Self) -> Self {
        Self::Sub(Box::new(self), Box::new(other))
    }

    pub fn mul(self, other: Self) -> Self {
        Self::Mul(Box::new(self), Box::new(other))
    }

    pub fn neg(self) -> Self {
        Self::Neg(Box::new(self))
    }

    pub fn scale(self, scalar: F2_128) -> Self {
        self.mul(Self::constant(scalar))
    }

    pub fn as_constant(&self) -> Option<F2_128> {
        match self {
            Expr::Const(value) => Some(*value),
            Expr::Add(left, right) => Some(left.as_constant()? + right.as_constant()?),
            Expr::Sub(left, right) => Some(left.as_constant()? - right.as_constant()?),
            Expr::Mul(left, right) => Some(left.as_constant()? * right.as_constant()?),
            Expr::Neg(inner) => Some(-inner.as_constant()?),
            Expr::Var(_) => None,
        }
    }

    /// Convert a linear expression into a sparse linear combination.
    pub fn to_linear_combination(&self) -> Result<LinearCombination, LinearizationError> {
        match self {
            Expr::Const(value) => Ok(LinearCombination::constant(*value)),
            Expr::Var(id) => Ok(LinearCombination::variable(*id)),
            Expr::Add(left, right) => Ok(left
                .to_linear_combination()?
                .add(right.to_linear_combination()?)),
            Expr::Sub(left, right) => Ok(left
                .to_linear_combination()?
                .sub(right.to_linear_combination()?)),
            Expr::Neg(inner) => Ok(inner.to_linear_combination()?.scale(-F2_128::from(1u64))),
            Expr::Mul(left, right) => {
                if let Some(scalar) = left.as_constant() {
                    Ok(right.to_linear_combination()?.scale(scalar))
                } else if let Some(scalar) = right.as_constant() {
                    Ok(left.to_linear_combination()?.scale(scalar))
                } else {
                    Err(LinearizationError::NonLinear)
                }
            }
        }
    }

    pub fn shift_vars(&mut self, offset: VarId) {
        match self {
            Expr::Const(_) => {}
            Expr::Var(id) => *id += offset,
            Expr::Add(left, right) | Expr::Sub(left, right) | Expr::Mul(left, right) => {
                left.shift_vars(offset);
                right.shift_vars(offset);
            }
            Expr::Neg(inner) => inner.shift_vars(offset),
        }
    }

    pub fn eval(&self, witness: &Witness) -> Result<F2_128, EvalError> {
        match self {
            Expr::Const(value) => Ok(*value),
            Expr::Var(id) => witness.get(*id),
            Expr::Add(left, right) => Ok(left.eval(witness)? + right.eval(witness)?),
            Expr::Sub(left, right) => Ok(left.eval(witness)? - right.eval(witness)?),
            Expr::Mul(left, right) => Ok(left.eval(witness)? * right.eval(witness)?),
            Expr::Neg(inner) => Ok(-inner.eval(witness)?),
        }
    }
}

/// Sparse linear expression over witness variables plus a constant term.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LinearCombination {
    pub terms: Vec<(VarId, F2_128)>,
    pub constant: F2_128,
}

#[allow(clippy::should_implement_trait)]
impl LinearCombination {
    pub fn constant(value: F2_128) -> Self {
        Self {
            terms: Vec::new(),
            constant: value,
        }
    }

    pub fn variable(id: VarId) -> Self {
        Self {
            terms: vec![(id, F2_128::from(1u64))],
            constant: F2_128::from(0u64),
        }
    }

    pub fn add(mut self, other: Self) -> Self {
        self.terms.extend(other.terms);
        self.constant = self.constant + other.constant;
        self
    }

    pub fn sub(self, other: Self) -> Self {
        self.add(other.scale(-F2_128::from(1u64)))
    }

    pub fn scale(mut self, scalar: F2_128) -> Self {
        for (_, coefficient) in &mut self.terms {
            *coefficient = *coefficient * scalar;
        }
        self.constant = self.constant * scalar;
        self
    }

    /// Coefficients over `[witness..., 1]`; the constant column is `witness_len`.
    pub fn coefficients(&self, witness_len: usize) -> Vec<(usize, F2_128)> {
        let mut coefficients = self.terms.clone();
        if self.constant != F2_128::from(0u64) {
            coefficients.push((witness_len, self.constant));
        }
        coefficients
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LinearizationError {
    #[error("expression is not linear")]
    NonLinear,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constraint {
    pub a: Expr,
    pub b: Expr,
    pub c: Expr,
}

impl Constraint {
    pub fn new(a: Expr, b: Expr, c: Expr) -> Self {
        Self { a, b, c }
    }

    pub fn shift_vars(&mut self, offset: VarId) {
        self.a.shift_vars(offset);
        self.b.shift_vars(offset);
        self.c.shift_vars(offset);
    }

    pub fn check(&self, witness: &Witness) -> Result<(), EvalError> {
        let lhs = self.a.eval(witness)? * self.b.eval(witness)?;
        let rhs = self.c.eval(witness)?;
        if lhs == rhs {
            Ok(())
        } else {
            Err(EvalError::Unsatisfied { lhs, rhs })
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ConstraintSystem {
    pub num_vars: usize,
    pub constraints: Vec<Constraint>,
    pub public_inputs: Vec<VarId>,
}

impl ConstraintSystem {
    pub fn new(num_vars: usize) -> Self {
        Self {
            num_vars,
            constraints: Vec::new(),
            public_inputs: Vec::new(),
        }
    }

    pub fn alloc(&mut self, count: usize) -> std::ops::Range<VarId> {
        let start = self.num_vars;
        self.num_vars += count;
        start..self.num_vars
    }

    /// Append another system, shifting its variable IDs by the current size.
    pub fn merge(&mut self, mut other: Self) -> VarId {
        let offset = self.num_vars;
        for constraint in &mut other.constraints {
            constraint.shift_vars(offset);
        }
        for public_input in &mut other.public_inputs {
            *public_input += offset;
        }
        self.constraints.append(&mut other.constraints);
        self.public_inputs.append(&mut other.public_inputs);
        self.num_vars += other.num_vars;
        offset
    }

    pub fn add_constraint(&mut self, a: Expr, b: Expr, c: Expr) -> usize {
        let index = self.constraints.len();
        self.constraints.push(Constraint::new(a, b, c));
        index
    }

    pub fn add_public_input(&mut self, var: VarId) {
        self.public_inputs.push(var);
    }

    pub fn check(&self, witness: &Witness) -> Result<(), ConstraintError> {
        if witness.len() < self.num_vars {
            return Err(ConstraintError::WitnessTooShort {
                expected: self.num_vars,
                actual: witness.len(),
            });
        }
        for &var in &self.public_inputs {
            if var >= self.num_vars {
                return Err(ConstraintError::PublicInputOutOfRange(var));
            }
        }
        for (index, constraint) in self.constraints.iter().enumerate() {
            constraint
                .check(witness)
                .map_err(|source| ConstraintError::Constraint { index, source })?;
        }
        Ok(())
    }

    pub fn is_satisfied(&self, witness: &Witness) -> bool {
        self.check(witness).is_ok()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Witness {
    values: Vec<F2_128>,
}

impl Witness {
    pub fn new(values: Vec<F2_128>) -> Self {
        Self { values }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn get(&self, id: VarId) -> Result<F2_128, EvalError> {
        self.values
            .get(id)
            .copied()
            .ok_or(EvalError::VarOutOfRange(id))
    }

    pub fn values(&self) -> &[F2_128] {
        &self.values
    }

    pub fn values_mut(&mut self) -> &mut [F2_128] {
        &mut self.values
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvalError {
    #[error("witness variable {0} is out of range")]
    VarOutOfRange(VarId),
    #[error("constraint is unsatisfied: lhs={lhs:?}, rhs={rhs:?}")]
    Unsatisfied { lhs: F2_128, rhs: F2_128 },
}

#[derive(Debug, Error)]
pub enum ConstraintError {
    #[error("witness has {actual} values, expected at least {expected}")]
    WitnessTooShort { expected: usize, actual: usize },
    #[error("public input variable {0} is out of range")]
    PublicInputOutOfRange(VarId),
    #[error("constraint {index} failed: {source}")]
    Constraint {
        index: usize,
        #[source]
        source: EvalError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_simple_multiplication() {
        let mut cs = ConstraintSystem::new(3);
        cs.add_constraint(Expr::var(0), Expr::var(1), Expr::var(2));
        let a = F2_128::from(6u64);
        let b = F2_128::from(7u64);
        let product = a * b;
        let good = Witness::new(vec![a, b, product]);
        assert!(cs.check(&good).is_ok());
        let bad = Witness::new(vec![a, b, product + F2_128::from(1u64)]);
        assert!(cs.check(&bad).is_err());
    }

    #[test]
    fn linearizes_expressions_and_rejects_products() {
        let linear = Expr::var(0)
            .add(Expr::constant(3u64))
            .to_linear_combination()
            .unwrap();
        assert_eq!(
            linear.coefficients(1),
            vec![(0, F2_128::from(1u64)), (1, F2_128::from(3u64))]
        );
        assert!(matches!(
            Expr::var(0).mul(Expr::var(1)).to_linear_combination(),
            Err(LinearizationError::NonLinear)
        ));
    }

    #[test]
    fn merges_systems_with_shifted_variables() {
        let mut first = ConstraintSystem::new(1);
        first.add_constraint(Expr::var(0), Expr::constant(1u64), Expr::constant(1u64));
        let mut second = ConstraintSystem::new(1);
        second.add_constraint(Expr::var(0), Expr::constant(1u64), Expr::constant(1u64));
        assert_eq!(first.merge(second), 1);
        assert_eq!(first.num_vars, 2);
        let witness = Witness::new(vec![F2_128::from(1u64), F2_128::from(1u64)]);
        first.check(&witness).unwrap();
    }

    #[test]
    fn rejects_out_of_range_variables() {
        let expr = Expr::var(3);
        let witness = Witness::new(vec![F2_128::from(1u64)]);
        assert!(matches!(
            expr.eval(&witness),
            Err(EvalError::VarOutOfRange(3))
        ));
    }

    #[test]
    fn constant_folding_matches_evaluation() {
        let expr = Expr::constant(3u64)
            .mul(Expr::constant(5u64))
            .add(Expr::constant(7u64))
            .neg();
        let witness = Witness::new(Vec::new());
        assert_eq!(expr.as_constant(), Some(expr.eval(&witness).unwrap()));
        assert_eq!(Expr::var(0).as_constant(), None);
        assert_eq!(Expr::var(0).add(Expr::constant(1u64)).as_constant(), None);
    }

    #[test]
    fn shift_vars_moves_every_variable() {
        let mut expr = Expr::var(0)
            .add(Expr::var(1))
            .mul(Expr::var(2).sub(Expr::constant(1u64)));
        let original = expr.clone();
        expr.shift_vars(3);

        let a = F2_128::from(2u64);
        let b = F2_128::from(4u64);
        let c = F2_128::from(9u64);
        let unshifted = Witness::new(vec![a, b, c]);
        let shifted = Witness::new(vec![
            F2_128::from(0u64),
            F2_128::from(0u64),
            F2_128::from(0u64),
            a,
            b,
            c,
        ]);
        assert_eq!(
            original.eval(&unshifted).unwrap(),
            expr.eval(&shifted).unwrap()
        );
    }

    #[test]
    fn linear_combination_arithmetic_is_sparse() {
        let combination = LinearCombination::variable(2)
            .scale(F2_128::from(5u64))
            .add(LinearCombination::constant(F2_128::from(3u64)))
            .sub(LinearCombination::variable(1));
        assert_eq!(
            combination.coefficients(4),
            vec![
                (2, F2_128::from(5u64)),
                (1, -F2_128::from(1u64)),
                (4, F2_128::from(3u64)),
            ]
        );

        let pure = LinearCombination::variable(0).scale(F2_128::from(2u64));
        assert_eq!(pure.clone().coefficients(1), vec![(0, F2_128::from(2u64))]);
        assert_eq!(
            pure.add(LinearCombination::constant(F2_128::from(0u64)))
                .coefficients(1),
            vec![(0, F2_128::from(2u64))]
        );
    }

    #[test]
    fn constraint_system_validates_public_inputs_and_witness_length() {
        let mut cs = ConstraintSystem::new(2);
        cs.add_constraint(Expr::var(0), Expr::constant(1u64), Expr::var(1));
        assert_eq!(cs.alloc(3), 2..5);
        assert_eq!(cs.num_vars, 5);
        assert_eq!(
            cs.add_constraint(
                Expr::constant(1u64),
                Expr::constant(1u64),
                Expr::constant(1u64)
            ),
            1
        );

        let short = Witness::new(vec![F2_128::from(1u64)]);
        assert!(matches!(
            cs.check(&short),
            Err(ConstraintError::WitnessTooShort {
                expected: 5,
                actual: 1
            })
        ));

        cs.add_public_input(7);
        let witness = Witness::new(vec![F2_128::from(0u64); 5]);
        assert!(matches!(
            cs.check(&witness),
            Err(ConstraintError::PublicInputOutOfRange(7))
        ));

        let mut satisfied = ConstraintSystem::new(2);
        satisfied.add_constraint(Expr::var(0), Expr::constant(1u64), Expr::var(1));
        let good = Witness::new(vec![F2_128::from(1u64), F2_128::from(1u64)]);
        assert!(satisfied.is_satisfied(&good));
        let mut bad = good.clone();
        bad.values_mut()[1] = F2_128::from(0u64);
        assert!(!satisfied.is_satisfied(&bad));
        assert!(!bad.is_empty());
        assert!(Witness::new(Vec::new()).is_empty());
    }
}

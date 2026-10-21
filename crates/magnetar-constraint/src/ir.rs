use crate::field::F61;
use thiserror::Error;

pub type VarId = usize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Const(F61),
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

    pub fn constant(value: impl Into<F61>) -> Self {
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

    pub fn scale(self, scalar: F61) -> Self {
        self.mul(Self::constant(scalar))
    }

    pub fn eval(&self, witness: &Witness) -> Result<F61, EvalError> {
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
    values: Vec<F61>,
}

impl Witness {
    pub fn new(values: Vec<F61>) -> Self {
        Self { values }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn get(&self, id: VarId) -> Result<F61, EvalError> {
        self.values
            .get(id)
            .copied()
            .ok_or(EvalError::VarOutOfRange(id))
    }

    pub fn values(&self) -> &[F61] {
        &self.values
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvalError {
    #[error("witness variable {0} is out of range")]
    VarOutOfRange(VarId),
    #[error("constraint is unsatisfied: lhs={lhs:?}, rhs={rhs:?}")]
    Unsatisfied { lhs: F61, rhs: F61 },
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
        let good = Witness::new(vec![F61::from(6), F61::from(7), F61::from(42)]);
        assert!(cs.check(&good).is_ok());
        let bad = Witness::new(vec![F61::from(6), F61::from(7), F61::from(41)]);
        assert!(cs.check(&bad).is_err());
    }

    #[test]
    fn rejects_out_of_range_variables() {
        let expr = Expr::var(3);
        let witness = Witness::new(vec![F61::from(1)]);
        assert!(matches!(
            expr.eval(&witness),
            Err(EvalError::VarOutOfRange(3))
        ));
    }
}

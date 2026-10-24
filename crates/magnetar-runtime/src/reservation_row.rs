//! Reservation-state transition row prototype.
//!
//! One row per CPU event. LR sets the reservation, SC succeeds only when the
//! reservation is valid and the addresses match, and stores/AMOs clear it.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

#[derive(Clone, Debug)]
pub struct ReservationRow {
    pub width: usize,
    pub addr: Vec<VarId>,
    pub res_addr: Vec<VarId>,
    pub pre_valid: VarId,
    pub post_valid: VarId,
    pub post_addr: Vec<VarId>,
    pub is_lr: VarId,
    pub is_sc: VarId,
    pub is_invalidate: VarId,
    pub is_other: VarId,
    pub success: VarId,
    pub match_addr: VarId,
    pub diff: Vec<VarId>,
    pub ors: Vec<VarId>,
    pub ands: Vec<VarId>,
    pub other_pre: VarId,
    pub mux: Vec<VarId>,
    pub one: VarId,
    pub zero: VarId,
    pub relation: BitRelation,
}

fn alloc(relation: &mut BitRelation, count: usize) -> Vec<VarId> {
    let start = relation.num_vars;
    relation.num_vars += count;
    (start..start + count).collect()
}

impl ReservationRow {
    pub fn new(width: usize) -> Self {
        let mut relation = BitRelation::new(0);
        let addr = alloc(&mut relation, width);
        let res_addr = alloc(&mut relation, width);
        let post_addr = alloc(&mut relation, width);
        let pre_valid = alloc(&mut relation, 1)[0];
        let post_valid = alloc(&mut relation, 1)[0];
        let is_lr = alloc(&mut relation, 1)[0];
        let is_sc = alloc(&mut relation, 1)[0];
        let is_invalidate = alloc(&mut relation, 1)[0];
        let is_other = alloc(&mut relation, 1)[0];
        let success = alloc(&mut relation, 1)[0];
        let match_addr = alloc(&mut relation, 1)[0];
        let zero = alloc(&mut relation, 1)[0];
        let one = alloc(&mut relation, 1)[0];
        relation.add(BitRow::new(vec![zero], vec![one], Vec::new()));
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        for flag in [
            pre_valid,
            post_valid,
            is_lr,
            is_sc,
            is_invalidate,
            is_other,
            success,
            match_addr,
        ] {
            relation.add(BitRow::new(vec![flag], vec![flag, one], Vec::new()));
        }
        for var in addr.iter().chain(&res_addr).chain(&post_addr) {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        relation.add(BitRow::new(
            vec![is_lr, is_sc, is_invalidate, is_other],
            vec![one],
            vec![one],
        ));
        let diff = alloc(&mut relation, width);
        let ors = alloc(&mut relation, width);
        let ands = alloc(&mut relation, width);
        let mut previous = zero;
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![addr[bit], res_addr[bit]],
                vec![one],
                vec![diff[bit]],
            ));
            relation.add(BitRow::new(
                vec![previous],
                vec![diff[bit]],
                vec![ands[bit]],
            ));
            relation.add(BitRow::new(
                vec![previous, diff[bit], ands[bit]],
                vec![one],
                vec![ors[bit]],
            ));
            previous = ors[bit];
        }
        relation.add(BitRow::new(
            vec![match_addr],
            vec![one],
            vec![one, previous],
        ));
        relation.add(BitRow::new(
            vec![pre_valid],
            vec![match_addr],
            vec![success],
        ));
        let other_pre = alloc(&mut relation, 1)[0];
        relation.add(BitRow::new(
            vec![is_other],
            vec![pre_valid],
            vec![other_pre],
        ));
        relation.add(BitRow::new(
            vec![is_lr, other_pre],
            vec![one],
            vec![post_valid],
        ));
        let mux = alloc(&mut relation, width);
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![is_lr],
                vec![addr[bit], res_addr[bit]],
                vec![mux[bit], res_addr[bit]],
            ));
            relation.add(BitRow::new(vec![mux[bit]], vec![one], vec![post_addr[bit]]));
        }
        Self {
            width,
            addr,
            res_addr,
            pre_valid,
            post_valid,
            post_addr,
            is_lr,
            is_sc,
            is_invalidate,
            is_other,
            success,
            match_addr,
            diff,
            ors,
            ands,
            other_pre,
            mux,
            one,
            zero,
            relation,
        }
    }

    pub fn witness(
        &self,
        addr: u64,
        res_addr: u64,
        pre_valid: bool,
        is_lr: bool,
        is_sc: bool,
        is_invalidate: bool,
    ) -> Vec<bool> {
        let mut bits = vec![false; self.relation.num_vars];
        bits[self.zero] = false;
        bits[self.one] = true;
        bits[self.is_lr] = is_lr;
        bits[self.is_sc] = is_sc;
        bits[self.is_invalidate] = is_invalidate;
        bits[self.is_other] = !(is_lr || is_sc || is_invalidate);
        bits[self.pre_valid] = pre_valid;
        let match_addr = addr == res_addr;
        bits[self.match_addr] = match_addr;
        let success = pre_valid && match_addr;
        bits[self.success] = success;
        let post_valid = if is_lr {
            true
        } else if is_sc || is_invalidate {
            false
        } else {
            pre_valid
        };
        bits[self.post_valid] = post_valid;
        let post_addr = if is_lr { addr } else { res_addr };
        for bit in 0..self.width {
            bits[self.addr[bit]] = (addr >> bit) & 1 == 1;
            bits[self.res_addr[bit]] = (res_addr >> bit) & 1 == 1;
            bits[self.post_addr[bit]] = (post_addr >> bit) & 1 == 1;
        }
        let mut previous = false;
        for bit in 0..self.width {
            let a = (addr >> bit) & 1 == 1;
            let b = (res_addr >> bit) & 1 == 1;
            let diff = a ^ b;
            bits[self.diff[bit]] = diff;
            bits[self.ands[bit]] = previous && diff;
            bits[self.ors[bit]] = previous ^ diff ^ (previous && diff);
            previous = bits[self.ors[bit]];
            bits[self.mux[bit]] = if is_lr { a } else { b };
        }
        bits[self.other_pre] = bits[self.is_other] && pre_valid;
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(bits: &[bool], vars: &[VarId]) -> u64 {
        vars.iter()
            .enumerate()
            .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit))
    }

    #[test]
    fn reservation_transitions() {
        let row = ReservationRow::new(8);
        let lr = row.witness(5, 0, false, true, false, false);
        assert!(row.relation.check(&lr));
        assert!(lr[row.post_valid]);
        assert_eq!(value(&lr, &row.post_addr), 5);

        let sc_ok = row.witness(5, 5, true, false, true, false);
        assert!(row.relation.check(&sc_ok));
        assert!(sc_ok[row.success]);
        assert!(!sc_ok[row.post_valid]);

        let sc_bad = row.witness(6, 5, true, false, true, false);
        assert!(row.relation.check(&sc_bad));
        assert!(!sc_bad[row.success]);

        let clear = row.witness(5, 5, true, false, false, true);
        assert!(row.relation.check(&clear));
        assert!(!clear[row.post_valid]);
    }
}

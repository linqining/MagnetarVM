//! Reference Sv39 page-table walker.
//!
//! This is a standalone MMU reference used to validate translation semantics.
//! The executor still runs in bare mode; wiring the walker into traces and
//! proof constraints is a separate step.

use thiserror::Error;

pub const PAGE_SHIFT: u32 = 12;
pub const PAGE_SIZE: u64 = 1 << PAGE_SHIFT;
pub const SATP_PPN_SHIFT: u32 = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privilege {
    User,
    Supervisor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Execute,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pte(u64);

impl Pte {
    pub fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub fn bits(self) -> u64 {
        self.0
    }

    pub fn valid(self) -> bool {
        self.0 & 1 != 0
    }

    pub fn readable(self) -> bool {
        self.0 & 2 != 0
    }

    pub fn writable(self) -> bool {
        self.0 & 4 != 0
    }

    pub fn executable(self) -> bool {
        self.0 & 8 != 0
    }

    pub fn user(self) -> bool {
        self.0 & 16 != 0
    }

    pub fn accessed(self) -> bool {
        self.0 & 64 != 0
    }

    pub fn dirty(self) -> bool {
        self.0 & 128 != 0
    }

    pub fn ppn(self) -> u64 {
        (self.0 >> 10) & ((1u64 << 44) - 1)
    }

    pub fn is_leaf(self) -> bool {
        self.readable() || self.executable()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MmuError {
    #[error("virtual address {0:#x} is not canonical for Sv39")]
    NonCanonical(u64),
    #[error("invalid PTE at level {level} index {index}: {pte:#x}")]
    InvalidPte { level: u32, index: u64, pte: u64 },
    #[error("permission denied for {access:?} at level {level}")]
    Permission { level: u32, access: Access },
    #[error("page-table access at physical address {0:#x} is out of bounds")]
    OutOfBounds(u64),
    #[error("superpage at level {level} has misaligned PPN {ppn:#x}")]
    MisalignedSuperpage { level: u32, ppn: u64 },
}

pub fn translate(
    root_ppn: u64,
    virtual_address: u64,
    access: Access,
    privilege: Privilege,
    memory: &[u8],
) -> Result<u64, MmuError> {
    if virtual_address >> 38 != 0 && virtual_address >> 38 != (1u64 << 26) - 1 {
        return Err(MmuError::NonCanonical(virtual_address));
    }
    let mut table = root_ppn;
    for level in (0..=2).rev() {
        let index = (virtual_address >> (PAGE_SHIFT + 9 * level)) & 0x1ff;
        let pte_address = (table << PAGE_SHIFT)
            .checked_add(index * 8)
            .ok_or(MmuError::OutOfBounds(table))?;
        let start = usize::try_from(pte_address).map_err(|_| MmuError::OutOfBounds(pte_address))?;
        let bytes = memory
            .get(start..start + 8)
            .ok_or(MmuError::OutOfBounds(pte_address))?;
        let pte = Pte::from_bits(u64::from_le_bytes(bytes.try_into().expect("eight bytes")));
        if !pte.valid() || (pte.writable() && !pte.readable()) {
            return Err(MmuError::InvalidPte {
                level,
                index,
                pte: pte.bits(),
            });
        }
        if pte.is_leaf() {
            if privilege == Privilege::User && !pte.user() {
                return Err(MmuError::Permission { level, access });
            }
            let permitted = match access {
                Access::Read => pte.readable(),
                Access::Write => pte.writable(),
                Access::Execute => pte.executable(),
            };
            if !permitted || !pte.accessed() || (access == Access::Write && !pte.dirty()) {
                return Err(MmuError::Permission { level, access });
            }
            let ppn = pte.ppn();
            let low_mask = (1u64 << (9 * level)) - 1;
            if level > 0 && ppn & low_mask != 0 {
                return Err(MmuError::MisalignedSuperpage { level, ppn });
            }
            let offset_mask = (1u64 << (PAGE_SHIFT + 9 * level)) - 1;
            return Ok((ppn << PAGE_SHIFT) | (virtual_address & offset_mask));
        }
        table = pte.ppn();
    }
    Err(MmuError::InvalidPte {
        level: 0,
        index: 0,
        pte: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: u64 = 1;
    const LEVEL1: u64 = 2;
    const LEVEL0: u64 = 3;

    fn write_pte(memory: &mut [u8], table: u64, index: u64, pte: Pte) {
        let offset = ((table << PAGE_SHIFT) + index * 8) as usize;
        memory[offset..offset + 8].copy_from_slice(&pte.bits().to_le_bytes());
    }

    fn leaf(ppn: u64, flags: u64) -> Pte {
        Pte::from_bits((ppn << 10) | flags)
    }

    fn table(ppn: u64) -> Pte {
        Pte::from_bits((ppn << 10) | 1)
    }

    #[test]
    fn translates_a_four_kibibyte_page() {
        let mut memory = vec![0u8; 0x10000];
        write_pte(&mut memory, ROOT, 0, table(LEVEL1));
        write_pte(&mut memory, LEVEL1, 0, table(LEVEL0));
        write_pte(&mut memory, LEVEL0, 4, leaf(0x8, 1 | 2 | 4 | 16 | 64 | 128));
        assert_eq!(
            translate(ROOT, 0x4000, Access::Read, Privilege::User, &memory).unwrap(),
            0x8000
        );
        assert_eq!(
            translate(ROOT, 0x4123, Access::Write, Privilege::User, &memory).unwrap(),
            0x8123
        );
    }

    #[test]
    fn translates_a_superpage() {
        let mut memory = vec![0u8; 0x10000];
        write_pte(&mut memory, ROOT, 0, table(LEVEL1));
        write_pte(&mut memory, LEVEL1, 1, leaf(0x200, 1 | 2 | 64));
        assert_eq!(
            translate(
                ROOT,
                0x20_0000 + 0x1234,
                Access::Read,
                Privilege::Supervisor,
                &memory
            )
            .unwrap(),
            0x20_1234
        );
    }

    #[test]
    fn rejects_invalid_and_unauthorized_translations() {
        let mut memory = vec![0u8; 0x10000];
        write_pte(&mut memory, ROOT, 0, table(LEVEL1));
        write_pte(&mut memory, LEVEL1, 0, table(LEVEL0));
        write_pte(&mut memory, LEVEL0, 4, leaf(0x8, 1 | 2 | 64));

        assert_eq!(
            translate(ROOT, 0x4000, Access::Write, Privilege::User, &memory),
            Err(MmuError::Permission {
                level: 0,
                access: Access::Write
            })
        );
        assert_eq!(
            translate(ROOT, 0x4000, Access::Read, Privilege::User, &memory),
            Err(MmuError::Permission {
                level: 0,
                access: Access::Read
            })
        );
        assert_eq!(
            translate(ROOT, 1 << 63, Access::Read, Privilege::Supervisor, &memory),
            Err(MmuError::NonCanonical(1 << 63))
        );
        assert!(matches!(
            translate(ROOT, 0x8000, Access::Read, Privilege::Supervisor, &memory),
            Err(MmuError::InvalidPte { .. })
        ));
        assert!(matches!(
            translate(1000, 0x4000, Access::Read, Privilege::Supervisor, &memory),
            Err(MmuError::OutOfBounds(_))
        ));
    }

    #[test]
    fn rejects_misaligned_superpages() {
        let mut memory = vec![0u8; 0x10000];
        write_pte(&mut memory, ROOT, 0, table(LEVEL1));
        write_pte(&mut memory, LEVEL1, 1, leaf(0x11, 1 | 2 | 64));
        assert_eq!(
            translate(
                ROOT,
                0x20_0000,
                Access::Read,
                Privilege::Supervisor,
                &memory
            ),
            Err(MmuError::MisalignedSuperpage {
                level: 1,
                ppn: 0x11
            })
        );
    }
}

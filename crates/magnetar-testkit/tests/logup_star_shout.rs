use magnetar_executor::execute;
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
use p3_field::PrimeCharacteristicRing;
use p3_challenger::HashChallenger;
use p3_keccak::Keccak256Hash;
use p3_multi_stark::logup_star::{
    LogupStarProof, Reader, ReaderWitness, TableLookup, TableWitness,
};
use p3_multilinear_util::point::Point;

type F = BinaryField128;

fn challenger() -> BinaryChallenger<F, HashChallenger<u8, Keccak256Hash, 32>> {
    BinaryChallenger::from_hasher(b"magnetar-logup-shout".to_vec(), Keccak256Hash)
}

fn eval_mle(values: &[F], point: &Point<F>) -> F {
    p3_multilinear_util::poly::Poly::new(values.to_vec()).eval_ext::<F>(point)
}

#[test]
fn logup_star_shout_reads_word_mode_rom() {
    let rows = std::env::var("ROWS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(16);
    let mut rom = Vec::new();
    for index in 0..rows - 1 {
        rom.push(
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 1,
                rs2: 0,
                imm: index as i64 + 1,
                shamt: 0,
            }
            .encode(),
        );
    }
    rom.push(Instruction::new(Op::Ecall).encode());
    let trace = execute(
        &ProgramImage::new(0x1000, rom),
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x100,
            stack_top: 0x1000_0100,
            max_cycles: 10_000_000,
        },
    )
    .unwrap();
    let witness = magnetar_runtime::binary_shout::BinaryShoutWitness::from_trace(&trace).unwrap();
    assert!(witness.is_32.iter().all(|bit| bit.value() == 0));
    let _cells = witness.cells;
    let cycles = witness.cycles;
    let columns = witness.rom.first().map_or(0, |row| row.len());

    // Table: ROM values, converted into the P3 binary field.
    let table_columns = (0..columns)
        .map(|column| {
            witness
                .rom
                .iter()
                .map(|row| F::from_repr(row[column].value()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let column_refs = table_columns
        .iter()
        .map(|column| column.as_slice())
        .collect::<Vec<_>>();
    let positions = (0..cycles)
        .map(|cycle| {
            if witness.valid[cycle].value() == 0 {
                return 0;
            }
            (0..witness.address_bits).fold(0usize, |address, bit| {
                if witness.address0[bit][cycle].value() != 0 {
                    address | (1 << bit)
                } else {
                    address
                }
            })
        })
        .collect::<Vec<_>>();

    // Reader values equal the table entry at the selected position.
    let reader_columns = (0..columns)
        .map(|column| {
            positions
                .iter()
                .map(|position| table_columns[column][*position])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let point = Point::new(
        (0..witness.cycle_bits)
            .map(|bit| F::from_repr((bit as u128) + 2))
            .collect::<Vec<_>>(),
    );
    let claims = reader_columns
        .iter()
        .map(|column| eval_mle(column, &point))
        .collect::<Vec<_>>();
    let readers = [Reader {
        point: &point,
        claims: &claims,
    }];
    let lookups = [TableLookup {
        num_variables: witness.address_bits,
        readers: &readers,
    }];
    let reader_witnesses = [ReaderWitness {
        positions: &positions,
    }];
    let witness = [TableWitness {
        columns: &column_refs,
        readers: &reader_witnesses,
    }];

    let started = std::time::Instant::now();
    let mut prover_challenger = challenger();
    let (proof, output) =
        LogupStarProof::<F, F>::prove(&lookups, &witness, &mut prover_challenger);
    eprintln!("logup* prove rows={} cycles={} cells={} prove={:?}", rows, cycles, _cells, started.elapsed());
    let started = std::time::Instant::now();
    let mut verifier_challenger = challenger();
    let verified = proof
        .verify(&lookups, &mut verifier_challenger)
        .expect("logup* Shout verifier");
    eprintln!("logup* verify={:?} proof_bytes={}", started.elapsed(), bincode::serialize(&proof).unwrap().len());
    assert_eq!(verified.tables.len(), output.tables.len());
    assert!(cycles >= rows);
}

use magnetar_constraint::F2_128;
use magnetar_executor::execute;
use magnetar_pcs::P3BinaryPcs;
use magnetar_proof::Pcs;
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
use magnetar_transcript::Sha256Transcript;
use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
use p3_challenger::HashChallenger;
use p3_field::Field as P3Field;
use p3_field::PrimeCharacteristicRing;
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

fn embed(position: usize) -> F {
    (0..usize::BITS as usize)
        .filter(|bit| (position >> bit) & 1 == 1)
        .map(|bit| F::interpolation_node(1 << bit))
        .sum()
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
    let address_bits = witness.address_bits;
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

    let started = std::time::Instant::now();
    // Commit table, reader and position columns with the binary P3 PCS.
    let pcs = P3BinaryPcs::new(100);
    let to_f2 = |value: F| F2_128::new(value.to_repr());
    let table_f2 = table_columns
        .iter()
        .map(|column| column.iter().map(|value| to_f2(*value)).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let reader_f2 = reader_columns
        .iter()
        .map(|column| column.iter().map(|value| to_f2(*value)).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let positions_f2 = positions
        .iter()
        .map(|position| to_f2(embed(*position)))
        .collect::<Vec<_>>();
    let table_commitments = table_f2
        .iter()
        .map(|column| pcs.commit(column).unwrap())
        .collect::<Vec<_>>();
    let reader_commitments = reader_f2
        .iter()
        .map(|column| pcs.commit(column).unwrap())
        .collect::<Vec<_>>();
    let position_commitment = pcs.commit(&positions_f2).unwrap();

    // Reader point is drawn after every commitment.
    let mut transcript = Sha256Transcript::new("magnetar-logup-shout-reader-point");
    for commitment in table_commitments
        .iter()
        .chain(&reader_commitments)
        .chain(core::iter::once(&position_commitment))
    {
        transcript.absorb("commitment", &pcs.commitment_bytes(commitment));
    }
    let point = Point::new(
        (0..witness.cycle_bits)
            .map(|_| {
                let bytes = transcript.challenge_bytes("reader-point", 16);
                F::from_repr(u128::from_le_bytes(bytes.try_into().expect("16 bytes")))
            })
            .collect::<Vec<_>>(),
    );
    let point_f2 = point
        .iter()
        .rev()
        .map(|coordinate| to_f2(*coordinate))
        .collect::<Vec<_>>();
    let claims = reader_columns
        .iter()
        .map(|column| eval_mle(column, &point))
        .collect::<Vec<_>>();
    let readers = [Reader {
        point: &point,
        claims: &claims,
    }];
    let lookups = [TableLookup {
        num_variables: address_bits,
        readers: &readers,
    }];
    let reader_witnesses = [ReaderWitness {
        positions: &positions,
    }];
    let witness = [TableWitness {
        columns: &column_refs,
        readers: &reader_witnesses,
    }];

    let mut prover_challenger = challenger();
    let (proof, output) = LogupStarProof::<F, F>::prove(&lookups, &witness, &mut prover_challenger);
    let mut verifier_challenger = challenger();
    let verified = proof
        .verify(&lookups, &mut verifier_challenger)
        .expect("logup* Shout verifier");
    assert_eq!(verified.tables.len(), 1);

    let prove_elapsed = started.elapsed();
    eprintln!(
        "logup* Shout rows={rows} cycles={cycles} cells={_cells} prove={prove_elapsed:?} logup_proof={}B",
        bincode::serialize(&proof).unwrap().len()
    );
    let verify_started = std::time::Instant::now();
    // The logup* claims are discharged against the committed columns.
    let table_point = output.table_point.as_slice();
    let table_point_f2 = table_point
        .iter()
        .rev()
        .map(|coordinate| to_f2(*coordinate))
        .collect::<Vec<_>>();
    let table_output = &verified.tables[0];
    for (column, (commitment, claim)) in table_commitments
        .iter()
        .zip(table_output.column_claims.iter())
        .enumerate()
    {
        let opening = pcs.open(&table_f2[column], &table_point_f2).unwrap();
        assert!(pcs
            .verify(commitment, &table_point_f2, to_f2(*claim), &opening)
            .unwrap());
    }
    let position_point_f2 = verified
        .position_point
        .iter()
        .rev()
        .map(|coordinate| to_f2(*coordinate))
        .collect::<Vec<_>>();
    let position_opening = pcs.open(&positions_f2, &position_point_f2).unwrap();
    assert!(pcs
        .verify(
            &position_commitment,
            &position_point_f2,
            to_f2(verified.tables[0].position_claims[0]),
            &position_opening
        )
        .unwrap());
    for (column, (commitment, claim)) in reader_commitments.iter().zip(claims.iter()).enumerate() {
        let opening = pcs.open(&reader_f2[column], &point_f2).unwrap();
        assert!(pcs
            .verify(commitment, &point_f2, to_f2(*claim), &opening)
            .unwrap());
    }

    eprintln!(
        "logup* Shout verify={:?} open_verify_done",
        verify_started.elapsed()
    );

    // A tampered reader claim must be rejected by the reduction.
    let mut bad_claims = claims.clone();
    bad_claims[0] += F::ONE;
    let bad_readers = [Reader {
        point: &point,
        claims: &bad_claims,
    }];
    let bad_lookups = [TableLookup {
        num_variables: address_bits,
        readers: &bad_readers,
    }];
    let mut bad_challenger = challenger();
    assert!(proof.verify(&bad_lookups, &mut bad_challenger).is_err());
    assert!(cycles >= rows);
}

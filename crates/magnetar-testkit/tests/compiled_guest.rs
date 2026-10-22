use magnetar_executor::ExecutionIo;
use magnetar_runtime::{
    decode_unified_proof, encode_unified_proof, prove_unified_trace, run_guest_elf,
    verify_unified_trace_statement,
};
use magnetar_spec::MachineConfig;

const HELLO_ELF: &[u8] = include_bytes!("fixtures/hello.elf");
const EXPECTED_OUTPUT: &[u8] = b"Hello, MagnetarVM!\n";

fn config() -> MachineConfig {
    MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x10000,
        stack_top: 0x1000_8000,
        max_cycles: 10_000,
    }
}

#[test]
fn compiled_guest_elf_runs_and_proves() {
    let mut io = ExecutionIo::default();
    let outcome = run_guest_elf(HELLO_ELF, config(), 8, &mut io).unwrap();

    assert_eq!(outcome.trace.io_output, EXPECTED_OUTPUT);
    assert_eq!(outcome.statement.output, EXPECTED_OUTPUT);
    assert_eq!(outcome.trace.exit_code, Some(0));
    assert!(outcome.trace.halted);

    let proof = prove_unified_trace(&outcome.trace, 64).unwrap();
    verify_unified_trace_statement(&outcome.statement, &outcome.trace, &proof, 64).unwrap();

    let encoded = encode_unified_proof(&proof).unwrap();
    let decoded = decode_unified_proof(&encoded).unwrap();
    verify_unified_trace_statement(&outcome.statement, &outcome.trace, &decoded, 64).unwrap();

    let mut tampered = outcome.statement.clone();
    tampered.output[0] ^= 1;
    assert!(verify_unified_trace_statement(&tampered, &outcome.trace, &proof, 64).is_err());
}

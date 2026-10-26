use magnetar_executor::ExecutionIo;
use magnetar_runtime::claim_native::{prove_claim_native, verify_claim_native};
use magnetar_runtime::run_guest_elf;
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
fn claim_native_guest_round_trips() {
    let mut io = ExecutionIo::default();
    let outcome = run_guest_elf(HELLO_ELF, config(), 8, &mut io).unwrap();
    assert_eq!(outcome.trace.io_output, EXPECTED_OUTPUT);
    let proof = prove_claim_native(&outcome.trace, 64).unwrap();
    verify_claim_native(&outcome.statement, &proof, 64).unwrap();
}

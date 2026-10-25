# Magnetar reference implementation — internal security review

Status: **internal self-review, not an external security audit.**

Scope: this repository at the commit shown in `git log -1`, including the
unified, chunked, gated-dual, access, Shout/Router and shift-expansion paths.
It is a correctness-first reference implementation.

## Threat model

- Prover: malicious, controls every proof field and witness outside the public
  statement.
- Verifier: honest, runs the Rust verifier on the supplied proof/statement.
- Public inputs: statement (ROM, config, initial/final state, trace commitment,
  trace length, IO), program image, and PCS verifier parameters.
- Not in scope: host OS, executor side channels, proof generation DoS,
  cryptographic primitives inside `vendor/`, or ZK/private IO.

## Trusted assumptions

1. SHA-256 is collision resistant and the transcript domain separation is
   sound.
2. The P3 binary-field PCS with the configured `security_level=100` parameters
   provides the intended binding/evaluation soundness.
3. The constraint IR/Spartan/lockstep reductions and their sum-checks are
   correct as implemented.
4. The verifier parameters (adaptive P3 tiers) are selected identically by
   prover and verifier from the statement/commitment shape.

## Checks performed

- Commitment/opening tampering rejects in unified, chunked access, combined
  access+aux, compact CPU, Twist/Shout/Router and gated-dual tests.
- Proof-only unified verification with the trace dropped
  (`unified_proof_round_trips_without_trace`).
- Statement/trace-commitment mismatch rejects in the trace-aware verifier.
- Gated dual `q=2/4/8` runs with both Direct and RingSwitch backends.
- Compact chunked proof rejects tampering of the whole-CPU witness and of a
  chunk chain `state_after` digest.
- D12 expansion tests compare expanded and original register files, including
  branch/jal/auipc/jalr fallback and x28-x31 preservation.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean.

## Findings / risks

| id | severity | finding | status |
|---|---|---|---|
| S1 | process | No independent external audit. | open |
| S2 | high-assurance | P3 parameters/pow tiers are engineering choices; no formal soundness proof or parameter audit in this repo. | open |
| S3 | medium | Chunked compact verification still consumes the trace for chunk state; unified verification is proof-only. | open |
| S4 | medium | Dynamic `jalr` programs fall back to the original bytecode; expansion is not universal. Semantics are preserved, but this is not the paper's fully expanded form. | accepted tradeoff |
| S5 | medium | Reference code is not constant-time; no side-channel review. | open |
| S6 | low | No ZK masking/private IO; the protocol is transparent. | by design |
| S7 | low | `SYS_READ` host input is public trace data in this reference; host/guest ABI is not a security boundary. | documented |

## Recommendations

1. Commission an external cryptographic/protocol audit before production.
2. Independently justify P3 parameter choices (security level, grinding bits,
   folding factor) and freeze them in a parameter specification.
3. Make chunked compact verification proof-only by adding chunk-boundary state
   commitments to the statement/proof, or document it as a trace-aware mode.
4. Replace dynamic-`jalr` fallback with the trace-level virtual expansion if the
   paper's full expansion form is required.
5. Add a side-channel/constant-time review and a reproducible build.

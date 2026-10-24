# Proof-only Router gap

`verify_binary_router_claims` no longer uses the witness for the main table
evals, but it still reconstructs several **public route vectors** from
`witness.routes`:

```text
offset_bits[3][cycle]
width_bits[4][cycle] (one-hot store width)
shift_code[cycle]
is_shift[cycle], is_store[cycle]
shift_q[h][cycle], shift_hq[h][cycle]
```

and compares them against committed table evals with random linear combinations.

These vectors are currently not committed, so a verifier cannot trust
proof-carried evals for them. Making Router proof-only requires:

1. commit `offset_bits`, `width_bits`, `shift_code`, `is_shift`, `is_store`;
2. commit `shift_q` and `shift_hq` (or derive them from committed selectors);
3. store their evaluations at the verifier challenges in `BinaryRouterProof`;
4. add the corresponding Mosaic opening points;
5. then replace `witness.routes[cycle]` in the verifier.

This is the same pattern used for BinaryTwist initial/read/write tables and for
Shout address/read tables, but Router needs more vectors and the q/hq selectors.

# What is already done

```text
BinaryTwist: proof-only (verify_binary_twist_from_proof)
BinaryShout: proof-only (witness argument unused)
BinaryRouter: table evals still depend on witness.routes
```

use magnetar_constraint::F2_128;
use p3_binary_field::{BinaryField128, TowerLevel};

#[test]
fn f2_128_and_p3_binary_field_share_representation() {
    let values = [
        1u128,
        2,
        3,
        0x1234_5678_9abc_def0,
        0xdead_beef_dead_beef_dead_beef_dead_beef,
        u128::MAX,
    ];
    for a in values {
        for b in values {
            let fa = F2_128::new(a);
            let fb = F2_128::new(b);
            let product = (fa * fb).value();
            let pa = BinaryField128::from_repr(a);
            let pb = BinaryField128::from_repr(b);
            let p3_product = (pa * pb).to_repr();
            assert_eq!(product, p3_product, "a={a:#x} b={b:#x}");
        }
    }
}

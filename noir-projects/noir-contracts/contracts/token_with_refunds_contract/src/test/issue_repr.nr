use dep::aztec::{
    prelude::{AztecAddress, U128, Point, PrivateContext},
    test::helpers::{cheatcodes, test_environment::TestEnvironment},
    encrypted_logs::encrypted_note_emission::encode_and_encrypt_note_with_keys_2
};

use crate::{types::{token_note::TokenNote, transparent_note::TransparentNote}, TokenWithRefunds};
use crate::types::balances_map::BalancesMap;

#[test]
fn wtf_issue() {
    let mut inputs = cheatcodes::get_private_context_inputs(2);
    let context = PrivateContext::new(inputs, 0);

    let funded_amount = 20000000000;
    let user = AztecAddress::from_field(1);
    let balances: BalancesMap<TokenNote, &mut PrivateContext> = BalancesMap::new(&mut context, 2);
    balances.add(user, U128::from_integer(funded_amount)).emit(encode_and_encrypt_note_with_keys_2(&mut context, Point::empty()));

    dep::aztec::oracle::debug_log::debug_log_format(
        "context.this_address() after: {0}",
        [context.this_address().to_field()]
    );

    assert(context.this_address().to_field() != 0, "this_address is zero");
}

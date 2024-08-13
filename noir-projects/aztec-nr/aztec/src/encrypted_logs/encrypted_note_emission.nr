use crate::{
    context::PrivateContext, note::{note_emission::NoteEmission, note_interface::NoteInterface},
    encrypted_logs::payload::compute_encrypted_note_log, oracle::logs_traits::LensForEncryptedLog,
    keys::getters::get_ovsk_app
};
use dep::protocol_types::{
    hash::sha256_to_field, address::AztecAddress, point::Point, abis::note_hash::NoteHash,
    constants::MAX_NOTE_HASHES_PER_CALL, utils::arrays::find_index
};

fn compute_raw_note_log<Note, let N: u32, let NB: u32, let M: u32>(
    context: PrivateContext,
    note: Note,
    ovsk_app: Field,
    ovpk: Point,
    ivpk: Point,
    recipient: AztecAddress
) -> (u32, [u8; M], Field) where Note: NoteInterface<N, NB>, [Field; N]: LensForEncryptedLog<N, M> {
    let note_header = note.get_header();
    let note_hash_counter = note_header.note_hash_counter;
    let storage_slot = note_header.storage_slot;

    let note_exists_index = find_index(
        context.note_hashes.storage,
        |n: NoteHash| n.counter == note_hash_counter
    );
    assert(
        note_exists_index as u32 != MAX_NOTE_HASHES_PER_CALL, "Can only emit a note log for an existing note."
    );

    let contract_address: AztecAddress = context.this_address();

    let encrypted_log: [u8; M] = compute_encrypted_note_log(
        contract_address,
        storage_slot,
        ovsk_app,
        ovpk,
        ivpk,
        recipient,
        note
    );
    let log_hash = sha256_to_field(encrypted_log);

    (note_hash_counter, encrypted_log, log_hash)
}

unconstrained fn compute_raw_note_log_unconstrained<Note, let N: u32, let NB: u32, let M: u32>(
    context: PrivateContext,
    note: Note,
    ovpk: Point,
    ivpk: Point,
    recipient: AztecAddress
) -> (u32, [u8; M], Field) where Note: NoteInterface<N, NB>, [Field; N]: LensForEncryptedLog<N, M> {
    let ovsk_app = get_ovsk_app(ovpk.hash());
    compute_raw_note_log(context, note, ovsk_app, ovpk, ivpk, recipient)
}

pub fn encode_and_encrypt_note<Note, let N: u32, let NB: u32, let M: u32>(
    context: &mut PrivateContext,
    ov: AztecAddress,
    iv: AztecAddress
) -> fn[(&mut PrivateContext, AztecAddress, AztecAddress)](NoteEmission<Note>) -> () where Note: NoteInterface<N, NB>, [Field; N]: LensForEncryptedLog<N, M> {
    | e: NoteEmission<Note> | {
        let header = context.get_header();
        let ovpk = header.get_ovpk_m(context, ov);
        let ivpk = header.get_ivpk_m(context, iv);
        let ovsk_app: Field  = context.request_ovsk_app(ovpk.hash());

        let (note_hash_counter, encrypted_log, log_hash) = compute_raw_note_log(*context, e.note, ovsk_app, ovpk, ivpk, iv);
        context.emit_raw_note_log(note_hash_counter, encrypted_log, log_hash);
    }
}

pub fn encode_and_encrypt_note_unconstrained<Note, let N: u32, let NB: u32, let M: u32>(
    context: &mut PrivateContext,
    ov: AztecAddress,
    iv: AztecAddress
) -> fn[(&mut PrivateContext, AztecAddress, AztecAddress)](NoteEmission<Note>) -> () where Note: NoteInterface<N, NB>, [Field; N]: LensForEncryptedLog<N, M> {
    | e: NoteEmission<Note> | {
        let header = context.get_header();
        // Note: We could save a lot of gates by obtaining the following keys in an unconstrained context but this
        // function is currently not used anywhere so we are not optimizing it.
        let ovpk = header.get_ovpk_m(context, ov);
        let ivpk = header.get_ivpk_m(context, iv);

        let (note_hash_counter, encrypted_log, log_hash) = compute_raw_note_log_unconstrained(*context, e.note, ovpk, ivpk, iv);
        context.emit_raw_note_log(note_hash_counter, encrypted_log, log_hash);
    }
}

pub fn encode_and_encrypt_note_with_keys<Note, let N: u32, let NB: u32, let M: u32>(
    context: &mut PrivateContext,
    ovpk: Point,
    ivpk: Point,
    recipient: AztecAddress
) -> fn[(&mut PrivateContext, Point, Point, AztecAddress)](NoteEmission<Note>) -> () where Note: NoteInterface<N, NB>, [Field; N]: LensForEncryptedLog<N, M> {
    | e: NoteEmission<Note> | {
        let ovsk_app: Field  = context.request_ovsk_app(ovpk.hash());

        let (note_hash_counter, encrypted_log, log_hash) = compute_raw_note_log(*context, e.note, ovsk_app, ovpk, ivpk, recipient);
        context.emit_raw_note_log(note_hash_counter, encrypted_log, log_hash);
    }
}

pub fn encode_and_encrypt_note_with_keys_unconstrained<Note, let N: u32, let NB: u32, let M: u32>(
    context: &mut PrivateContext,
    ovpk: Point,
    ivpk: Point,
    recipient: AztecAddress
) -> fn[(&mut PrivateContext, Point, Point, AztecAddress)](NoteEmission<Note>) -> () where Note: NoteInterface<N, NB>, [Field; N]: LensForEncryptedLog<N, M> {
    | e: NoteEmission<Note> | {
        let (note_hash_counter, encrypted_log, log_hash) = compute_raw_note_log_unconstrained(*context, e.note, ovpk, ivpk, recipient);
        context.emit_raw_note_log(note_hash_counter, encrypted_log, log_hash);
    }
}


// =============================================================================================================

use dep::protocol_types::scalar::Scalar;
use std::{
    embedded_curve_ops::fixed_base_scalar_mul as derive_public_key,
    hash::from_field_unsafe as fr_to_fq_unsafe, field::bn254::decompose
};

use crate::{
    event::event_interface::EventInterface, oracle::unsafe_rand::unsafe_rand,
    utils::point::point_to_bytes,
    encrypted_logs::{
    header::EncryptedLogHeader, incoming_body::EncryptedLogIncomingBody,
    outgoing_body::EncryptedLogOutgoingBody
}
};

fn fr_to_fq(r: Field) -> Scalar {
    let (lo, hi) = decompose(r);

    Scalar { lo, hi }
}


fn generate_ephemeral_key_pair() -> (Scalar, Point) {
    // @todo Need to draw randomness from the full domain of Fq not only Fr
    // We use the unsafe version of `fr_to_fq` because multi_scalar_mul (called by derive_public_key) will constrain
    // the scalars.
    let eph_sk = fr_to_fq_unsafe(unsafe_rand());
    let eph_pk = derive_public_key(eph_sk);

    (eph_sk, eph_pk)
}

pub fn compute_encrypted_note_log_2<Note, let N: u32, let NB: u32, let M: u32>(
    contract_address: AztecAddress,
    storage_slot: Field,
    ovsk_app: Field,
    ovpk: Point,
    ivpk: Point,
    recipient: AztecAddress,
    note: Note
) -> [u8; M] where Note: NoteInterface<N, NB> {
    let (eph_sk, eph_pk) = generate_ephemeral_key_pair();

    let header = EncryptedLogHeader::new(contract_address);

    let incoming_header_ciphertext: [u8; 48] = header.compute_ciphertext(eph_sk, ivpk);
    let outgoing_header_ciphertext: [u8; 48] = header.compute_ciphertext(eph_sk, ovpk);
    let incoming_body_ciphertext = EncryptedLogIncomingBody::from_note(note, storage_slot).compute_ciphertext(eph_sk, ivpk);
    let outgoing_body_ciphertext: [u8; 144] = EncryptedLogOutgoingBody::new(eph_sk, recipient, ivpk).compute_ciphertext(fr_to_fq(ovsk_app), eph_pk);

    let mut encrypted_bytes: [u8; M] = [0; M];
    // @todo We ignore the tags for now 

    let eph_pk_bytes = point_to_bytes(eph_pk);
    for i in 0..32 {
        encrypted_bytes[64 + i] = eph_pk_bytes[i];
    }
    for i in 0..48 {
        encrypted_bytes[96 + i] = incoming_header_ciphertext[i];
        encrypted_bytes[144 + i] = outgoing_header_ciphertext[i];
    }
    for i in 0..144 {
        encrypted_bytes[192 + i] = outgoing_body_ciphertext[i];
    }
    // Then we fill in the rest as the incoming body ciphertext
    let size = M - 336;
    assert_eq(size, incoming_body_ciphertext.len(), "ciphertext length mismatch");
    for i in 0..size {
        encrypted_bytes[336 + i] = incoming_body_ciphertext[i];
    }

    // Current unoptimized size of the encrypted log
    // incoming_tag (32 bytes)
    // outgoing_tag (32 bytes)
    // eph_pk (32 bytes)
    // incoming_header (48 bytes)
    // outgoing_header (48 bytes)
    // outgoing_body (144 bytes)
    // incoming_body_fixed (64 bytes)
    // incoming_body_variable (N * 32 bytes + 16 bytes padding)
    encrypted_bytes
}

fn compute_raw_note_log_2<Note, let N: u32, let NB: u32, let M: u32>(
    context: PrivateContext,
    note: Note,
    ovsk_app: Field,
    ovpk: Point,
    ivpk: Point,
    recipient: AztecAddress
) -> (u32, [u8; M], Field) where Note: NoteInterface<N, NB>, [Field; N]: LensForEncryptedLog<N, M> {
    // let note_header = note.get_header();
    // let note_hash_counter = note_header.note_hash_counter;
    // let storage_slot = note_header.storage_slot;

    // let contract_address: AztecAddress = context.this_address();

    let encrypted_log: [u8; M] = compute_encrypted_note_log_2(
        AztecAddress::zero(),
        0,
        ovsk_app,
        ovpk,
        ivpk,
        recipient,
        note
    );
    // let log_hash = sha256_to_field(encrypted_log);

    (0, encrypted_log, 0)
}

pub fn encode_and_encrypt_note_with_keys_2<Note, let N: u32, let NB: u32, let M: u32>(
    context: &mut PrivateContext,
    ovpk: Point,
    ivpk: Point,
    recipient: AztecAddress
) -> fn[(&mut PrivateContext, Point, Point, AztecAddress)](NoteEmission<Note>) -> () where Note: NoteInterface<N, NB>, [Field; N]: LensForEncryptedLog<N, M> {
    | e: NoteEmission<Note> | {
        let ovsk_app: Field  = context.request_ovsk_app(ovpk.hash());

        let (note_hash_counter, encrypted_log, log_hash) = compute_raw_note_log_2(*context, e.note, ovsk_app, ovpk, ivpk, recipient);
        context.push_nullifier(log_hash);
    }
}
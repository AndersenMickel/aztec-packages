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

use dep::protocol_types::{constants::GENERATOR_INDEX__SYMMETRIC_KEY, scalar::Scalar, utils::arr_copy_slice};
use crate::utils::point::point_to_bytes;
use std::{hash::sha256, embedded_curve_ops::multi_scalar_mul};

// when context was second in the closure env it has not failed (Point, &mut PrivateContext)
pub fn encode_and_encrypt_note_with_keys_2<Note, let N: u32, let NB: u32, let M: u32>(
    context: &mut PrivateContext,
    ovpk: Point
) -> fn[(&mut PrivateContext, Point)](NoteEmission<Note>) -> () where Note: NoteInterface<N, NB>, [Field; N]: LensForEncryptedLog<N, M> {
    | e: NoteEmission<Note> | {
        // let ovpk = Point::empty();
        let ovsk_app: Field  = context.request_ovsk_app(ovpk.hash());

        let iterator_len = if N > M { M } else { N };
        for i in 0..iterator_len {
        }

        context.push_nullifier(0);
    }
}

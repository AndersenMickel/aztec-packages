// A contract used for running benchmarks.
// We should try to change this contract as little as possible, since any modification
// would alter the metrics we're capturing in the benchmarks. We aim to keep the
// subject being tested as unmodified as possible to accurately detect changes in metrics.

contract Benchmarking {
    use dep::aztec::prelude::{AztecAddress, FunctionSelector, NoteHeader, NoteGetterOptions, Map, PublicMutable, PrivateSet};
    use dep::value_note::{utils::{increment, decrement}, value_note::ValueNote};
    use dep::aztec::context::gas::GasOpts;

    #[aztec(storage)]
    struct Storage {
        notes: Map<AztecAddress, PrivateSet<ValueNote>>,
        balances: Map<AztecAddress, PublicMutable<Field>>,
    }

    // Creates a new value note for the target owner. This method initializes an initial set of notes.
    #[aztec(private)]
    fn create_note(owner: AztecAddress, outgoing_viewer: AztecAddress, value: Field) {
        // Increment the value note for the specified owner
        // docs:start:increment_valuenote
        increment(storage.notes.at(owner), value, owner, outgoing_viewer);
        // docs:end:increment_valuenote
    }

    // Deletes a note at a specific index in the set and creates a new one with the same value.
    // Passing in the note index ensures different notes are consumed when sending multiple transactions
    // landing on the same block. For details, see:
    // https://discourse.aztec.network/t/utxo-concurrency-issues-for-private-state/635
    #[aztec(private)]
    fn recreate_note(owner: AztecAddress, outgoing_viewer: AztecAddress, index: u32) {
        let owner_notes = storage.notes.at(owner);
        let mut getter_options = NoteGetterOptions::new();
        let notes = owner_notes.pop_notes(getter_options.set_limit(1).set_offset(index));
        let note = notes.get(0);
        // Recreate the note with the same value
        increment(owner_notes, note.value, owner, outgoing_viewer);
    }

    // Reads and writes to public storage, then enqueues a call to another public function.
    #[aztec(public)]
    fn increment_balance(owner: AztecAddress, value: Field) {
        let current = storage.balances.at(owner).read();
        storage.balances.at(owner).write(current + value);
        // Broadcast the updated balance to the specified owner
        Benchmarking::at(context.this_address()).broadcast(owner).call(&mut context);
    }

    // Emits a public log with the current balance of the specified owner.
    #[aztec(public)]
    fn broadcast(owner: AztecAddress) {
        context.emit_unencrypted_log(storage.balances.at(owner).read());
    }
}

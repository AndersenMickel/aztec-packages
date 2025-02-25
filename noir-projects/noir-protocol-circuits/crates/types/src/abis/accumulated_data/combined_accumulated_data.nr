use crate::{
    hash::{compute_tx_logs_hash, compute_tx_note_logs_hash},
    abis::{
    accumulated_data::public_accumulated_data::PublicAccumulatedData, note_hash::ScopedNoteHash,
    nullifier::Nullifier, public_data_update_request::PublicDataUpdateRequest,
    log_hash::{LogHash, NoteLogHash, ScopedLogHash}, gas::Gas, side_effect::{Ordered, Positioned}
},
    messaging::l2_to_l1_message::ScopedL2ToL1Message,
    constants::{
    MAX_NOTE_HASHES_PER_TX, MAX_NULLIFIERS_PER_TX, MAX_L2_TO_L1_MSGS_PER_TX,
    MAX_PUBLIC_DATA_UPDATE_REQUESTS_PER_TX, COMBINED_ACCUMULATED_DATA_LENGTH,
    MAX_UNENCRYPTED_LOGS_PER_TX, MAX_NOTE_ENCRYPTED_LOGS_PER_TX, MAX_ENCRYPTED_LOGS_PER_TX
},
    hash::silo_note_hash,
    utils::{arrays::{array_merge, assert_sorted_array, assert_deduped_array, check_permutation}, reader::Reader},
    traits::{Empty, Serialize, Deserialize}
};

struct CombineHints {
    sorted_note_hashes: [ScopedNoteHash; MAX_NOTE_HASHES_PER_TX],
    sorted_note_hashes_indexes: [u32; MAX_NOTE_HASHES_PER_TX],
    sorted_note_encrypted_logs_hashes: [LogHash; MAX_NOTE_ENCRYPTED_LOGS_PER_TX],
    sorted_note_encrypted_logs_hashes_indexes: [u32; MAX_NOTE_ENCRYPTED_LOGS_PER_TX],
    sorted_encrypted_logs_hashes: [ScopedLogHash; MAX_ENCRYPTED_LOGS_PER_TX],
    sorted_encrypted_logs_hashes_indexes: [u32; MAX_ENCRYPTED_LOGS_PER_TX],
    sorted_unencrypted_logs_hashes: [ScopedLogHash; MAX_UNENCRYPTED_LOGS_PER_TX],
    sorted_unencrypted_logs_hashes_indexes: [u32; MAX_UNENCRYPTED_LOGS_PER_TX],
    // the public data update requests are sorted by their leaf index AND counter
    sorted_public_data_update_requests: [PublicDataUpdateRequest; MAX_PUBLIC_DATA_UPDATE_REQUESTS_PER_TX],
    sorted_public_data_update_requests_indexes: [u32; MAX_PUBLIC_DATA_UPDATE_REQUESTS_PER_TX],
    // THEN deduplicated based on their leaf slot
    deduped_public_data_update_requests: [PublicDataUpdateRequest; MAX_PUBLIC_DATA_UPDATE_REQUESTS_PER_TX],
    deduped_public_data_update_requests_runs: [u32; MAX_PUBLIC_DATA_UPDATE_REQUESTS_PER_TX],
}

struct CombinedAccumulatedData {
    note_hashes: [Field; MAX_NOTE_HASHES_PER_TX],
    nullifiers: [Field; MAX_NULLIFIERS_PER_TX],
    l2_to_l1_msgs: [ScopedL2ToL1Message; MAX_L2_TO_L1_MSGS_PER_TX],

    note_encrypted_logs_hashes: [LogHash; MAX_NOTE_ENCRYPTED_LOGS_PER_TX],
    encrypted_logs_hashes: [ScopedLogHash; MAX_ENCRYPTED_LOGS_PER_TX], 
    unencrypted_logs_hashes: [ScopedLogHash; MAX_UNENCRYPTED_LOGS_PER_TX],

    // Here so that the gas cost of this request can be measured by circuits, without actually needing to feed in the
    // variable-length data.
    note_encrypted_log_preimages_length: Field,
    encrypted_log_preimages_length: Field,
    unencrypted_log_preimages_length: Field,

    public_data_update_requests: [PublicDataUpdateRequest; MAX_PUBLIC_DATA_UPDATE_REQUESTS_PER_TX],

    gas_used: Gas,
}

fn asc_sort_by_counters<T>(a: T, b: T) -> bool where T: Ordered {
    a.counter() <= b.counter()
}

impl CombinedAccumulatedData {
    pub fn combine(
        non_revertible: PublicAccumulatedData,
        revertible: PublicAccumulatedData,
        combine_hints: CombineHints
    ) -> Self {
        let merged_note_hashes = array_merge(non_revertible.note_hashes, revertible.note_hashes);
        assert_sorted_array(
            merged_note_hashes,
            combine_hints.sorted_note_hashes,
            combine_hints.sorted_note_hashes_indexes,
            asc_sort_by_counters
        );

        let mut siloed_note_hashes = [0; MAX_NOTE_HASHES_PER_TX];
        let sorted_note_hashes = combine_hints.sorted_note_hashes;
        let tx_hash = non_revertible.nullifiers[0].value;
        for i in 0..sorted_note_hashes.len() {
            let note_hash = sorted_note_hashes[i];
            siloed_note_hashes[i] = if note_hash.counter() == 0 {
                // If counter is zero, the note hash was emitted from private and has been siloed in private_kernel_tail_to_public.
                note_hash.value()
            } else {
                silo_note_hash(note_hash, tx_hash, i)
            };
        }

        let merged_public_data_update_requests = array_merge(
            non_revertible.public_data_update_requests,
            revertible.public_data_update_requests
        );

        // Just check a permutation here...
        check_permutation(
            merged_public_data_update_requests,
            combine_hints.sorted_public_data_update_requests,
            combine_hints.sorted_public_data_update_requests_indexes
        );
        // ...because the ordering checks are done here.
        assert_deduped_array(
            combine_hints.sorted_public_data_update_requests,
            combine_hints.deduped_public_data_update_requests,
            combine_hints.deduped_public_data_update_requests_runs
        );

        let merged_note_encrypted_logs_hashes = array_merge(
            non_revertible.note_encrypted_logs_hashes,
            revertible.note_encrypted_logs_hashes
        );
        assert_sorted_array(
            merged_note_encrypted_logs_hashes,
            combine_hints.sorted_note_encrypted_logs_hashes,
            combine_hints.sorted_note_encrypted_logs_hashes_indexes,
            asc_sort_by_counters
        );

        let merged_encrypted_logs_hashes = array_merge(
            non_revertible.encrypted_logs_hashes,
            revertible.encrypted_logs_hashes
        );
        assert_sorted_array(
            merged_encrypted_logs_hashes,
            combine_hints.sorted_encrypted_logs_hashes,
            combine_hints.sorted_encrypted_logs_hashes_indexes,
            asc_sort_by_counters
        );

        let merged_unencrypted_logs_hashes = array_merge(
            non_revertible.unencrypted_logs_hashes,
            revertible.unencrypted_logs_hashes
        );
        assert_sorted_array(
            merged_unencrypted_logs_hashes,
            combine_hints.sorted_unencrypted_logs_hashes,
            combine_hints.sorted_unencrypted_logs_hashes_indexes,
            asc_sort_by_counters
        );

        let note_encrypted_log_preimages_length = non_revertible.note_encrypted_logs_hashes.fold(0, |a, b: LogHash| a + b.length)
            + revertible.note_encrypted_logs_hashes.fold(0, |a, b: LogHash| a + b.length);
        let encrypted_log_preimages_length = non_revertible.encrypted_logs_hashes.fold(0, |a, b: ScopedLogHash| a + b.log_hash.length)
            + revertible.encrypted_logs_hashes.fold(0, |a, b: ScopedLogHash| a + b.log_hash.length);
        let unencrypted_log_preimages_length = non_revertible.unencrypted_logs_hashes.fold(0, |a, b: ScopedLogHash| a + b.log_hash.length)
            + revertible.unencrypted_logs_hashes.fold(0, |a, b: ScopedLogHash| a + b.log_hash.length);
        CombinedAccumulatedData {
            note_hashes: siloed_note_hashes,
            nullifiers: array_merge(non_revertible.nullifiers, revertible.nullifiers).map(|n: Nullifier| n.value),
            l2_to_l1_msgs: array_merge(non_revertible.l2_to_l1_msgs, revertible.l2_to_l1_msgs),
            note_encrypted_logs_hashes: combine_hints.sorted_note_encrypted_logs_hashes,
            encrypted_logs_hashes: combine_hints.sorted_encrypted_logs_hashes,
            unencrypted_logs_hashes: combine_hints.sorted_unencrypted_logs_hashes,
            note_encrypted_log_preimages_length,
            encrypted_log_preimages_length,
            unencrypted_log_preimages_length,
            public_data_update_requests: combine_hints.deduped_public_data_update_requests,
            gas_used: revertible.gas_used + non_revertible.gas_used
        }
    }
}

impl Empty for CombinedAccumulatedData {
    fn empty() -> Self {
        CombinedAccumulatedData {
            note_hashes: [0; MAX_NOTE_HASHES_PER_TX],
            nullifiers: [0; MAX_NULLIFIERS_PER_TX],
            l2_to_l1_msgs: [ScopedL2ToL1Message::empty(); MAX_L2_TO_L1_MSGS_PER_TX],
            note_encrypted_logs_hashes: [LogHash::empty(); MAX_NOTE_ENCRYPTED_LOGS_PER_TX],
            encrypted_logs_hashes: [ScopedLogHash::empty(); MAX_ENCRYPTED_LOGS_PER_TX],
            unencrypted_logs_hashes: [ScopedLogHash::empty(); MAX_UNENCRYPTED_LOGS_PER_TX],
            note_encrypted_log_preimages_length: 0,
            encrypted_log_preimages_length: 0,
            unencrypted_log_preimages_length: 0,
            public_data_update_requests: [PublicDataUpdateRequest::empty(); MAX_PUBLIC_DATA_UPDATE_REQUESTS_PER_TX],
            gas_used: Gas::empty()
        }
    }
}

impl Serialize<COMBINED_ACCUMULATED_DATA_LENGTH> for CombinedAccumulatedData {
  fn serialize(self) -> [Field; COMBINED_ACCUMULATED_DATA_LENGTH] {
    let mut fields: BoundedVec<Field, COMBINED_ACCUMULATED_DATA_LENGTH> = BoundedVec::new();

    fields.extend_from_array(self.note_hashes);
    fields.extend_from_array(self.nullifiers);
    for i in 0..self.l2_to_l1_msgs.len() {
        fields.extend_from_array(self.l2_to_l1_msgs[i].serialize());
    }
    for i in 0..self.note_encrypted_logs_hashes.len() {
      fields.extend_from_array(self.note_encrypted_logs_hashes[i].serialize());
    }
    for i in 0..self.encrypted_logs_hashes.len() {
      fields.extend_from_array(self.encrypted_logs_hashes[i].serialize());
    }
    for i in 0..self.unencrypted_logs_hashes.len() {
      fields.extend_from_array(self.unencrypted_logs_hashes[i].serialize());
    }
    fields.push(self.note_encrypted_log_preimages_length);
    fields.push(self.encrypted_log_preimages_length);
    fields.push(self.unencrypted_log_preimages_length);

    for i in 0..MAX_PUBLIC_DATA_UPDATE_REQUESTS_PER_TX {
      fields.extend_from_array(self.public_data_update_requests[i].serialize());
    }

    fields.extend_from_array(self.gas_used.serialize());

    assert_eq(fields.len(), COMBINED_ACCUMULATED_DATA_LENGTH);

    fields.storage
  }
}

impl Deserialize<COMBINED_ACCUMULATED_DATA_LENGTH> for CombinedAccumulatedData {
  fn deserialize(fields: [Field; COMBINED_ACCUMULATED_DATA_LENGTH]) -> CombinedAccumulatedData {
    let mut reader = Reader::new(fields);

    let item = CombinedAccumulatedData {
        note_hashes: reader.read_array([0; MAX_NOTE_HASHES_PER_TX]),
        nullifiers: reader.read_array([0; MAX_NULLIFIERS_PER_TX]),
        l2_to_l1_msgs: reader.read_struct_array(ScopedL2ToL1Message::deserialize,[ScopedL2ToL1Message::empty(); MAX_L2_TO_L1_MSGS_PER_TX]),
        note_encrypted_logs_hashes: reader.read_struct_array(LogHash::deserialize, [LogHash::empty(); MAX_NOTE_ENCRYPTED_LOGS_PER_TX]),
        encrypted_logs_hashes: reader.read_struct_array(ScopedLogHash::deserialize, [ScopedLogHash::empty(); MAX_ENCRYPTED_LOGS_PER_TX]),
        unencrypted_logs_hashes: reader.read_struct_array(ScopedLogHash::deserialize, [ScopedLogHash::empty(); MAX_UNENCRYPTED_LOGS_PER_TX]),
        note_encrypted_log_preimages_length: reader.read(),
        encrypted_log_preimages_length: reader.read(),
        unencrypted_log_preimages_length: reader.read(),
        public_data_update_requests: reader.read_struct_array(PublicDataUpdateRequest::deserialize, [PublicDataUpdateRequest::empty(); MAX_PUBLIC_DATA_UPDATE_REQUESTS_PER_TX]),
        gas_used: reader.read_struct(Gas::deserialize),
    };
    reader.finish();
    item
  }
}

impl Eq for CombinedAccumulatedData {
  fn eq(self, other: Self) -> bool {
    (self.note_hashes == other.note_hashes) &
    (self.nullifiers == other.nullifiers) &
    (self.l2_to_l1_msgs == other.l2_to_l1_msgs) &
    (self.note_encrypted_logs_hashes == other.note_encrypted_logs_hashes) &
    (self.encrypted_logs_hashes == other.encrypted_logs_hashes) &
    (self.unencrypted_logs_hashes == other.unencrypted_logs_hashes) &
    (self.note_encrypted_log_preimages_length == other.note_encrypted_log_preimages_length) &
    (self.encrypted_log_preimages_length == other.encrypted_log_preimages_length) &
    (self.unencrypted_log_preimages_length == other.unencrypted_log_preimages_length) &
    (self.public_data_update_requests == other.public_data_update_requests) &
    (self.gas_used == other.gas_used)
  }
}

#[test]
fn serialization_of_empty() {
    let item = CombinedAccumulatedData::empty();
    let serialized = item.serialize();
    let deserialized = CombinedAccumulatedData::deserialize(serialized);
    assert(item.eq(deserialized));
}

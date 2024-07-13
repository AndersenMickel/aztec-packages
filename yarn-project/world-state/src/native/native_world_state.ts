/* eslint-disable @typescript-eslint/no-unused-vars */
import { type L2Block, MerkleTreeId, SiblingPath, TxEffect } from '@aztec/circuit-types';
import {
  AppendOnlyTreeSnapshot,
  ContentCommitment,
  Fr,
  GlobalVariables,
  Header,
  MAX_NEW_NOTE_HASHES_PER_TX,
  MAX_NEW_NULLIFIERS_PER_TX,
  MAX_TOTAL_PUBLIC_DATA_UPDATE_REQUESTS_PER_TX,
  NUMBER_OF_L1_L2_MESSAGES_PER_ROLLUP,
  NullifierLeaf,
  NullifierLeafPreimage,
  PartialStateReference,
  PublicDataTreeLeaf,
  PublicDataTreeLeafPreimage,
  StateReference,
} from '@aztec/circuits.js';
import { padArrayEnd } from '@aztec/foundation/collection';
import { serializeToBuffer } from '@aztec/foundation/serialize';
import type { IndexedTreeLeafPreimage } from '@aztec/foundation/trees';
import type { BatchInsertionResult } from '@aztec/merkle-tree';

import bindings from 'bindings';
import { Decoder, Encoder, addExtension } from 'msgpackr';
import { isAnyArrayBuffer } from 'util/types';

import { type MerkleTreeDb, type TreeSnapshots } from '../world-state-db/merkle_tree_db.js';
import {
  type HandleL2BlockAndMessagesResult,
  type IndexedTreeId,
  type MerkleTreeLeafType,
  type TreeInfo,
} from '../world-state-db/merkle_tree_operations.js';
import {
  MessageHeader,
  type NativeInstance,
  SerializedIndexedLeaf,
  SerializedLeafValue,
  TypedMessage,
  WorldStateMessageType,
  type WorldStateRequest,
  type WorldStateResponse,
  treeStateReferenceToSnapshot,
  worldStateRevision,
} from './message.js';

// small extension to pack an NodeJS Fr instance to a representation that the C++ code can understand
// this only works for writes. Unpacking from C++ can't create Fr instances because the data is passed
// as raw, untagged, buffers. On the NodeJS side we don't know what the buffer represents
// Adding a tag would be a solution, but it would have to be done on both sides and it's unclear where else
// C++ fr instances are sent/received/stored.
addExtension({
  Class: Fr,
  write: fr => fr.toBuffer(),
});

export class NativeWorldStateService implements MerkleTreeDb {
  private nextMessageId = 1;

  private encoder = new Encoder({
    // always encode JS objects as MessagePack maps
    // this makes it compatible with other MessagePack decoders
    useRecords: false,
    int64AsType: 'bigint',
  });

  private decoder = new Decoder({
    useRecords: false,
    int64AsType: 'bigint',
  });

  protected constructor(private instance: NativeInstance) {}

  static async create(libraryName: string, className: string, dataDir: string): Promise<NativeWorldStateService> {
    const library = bindings(libraryName);
    const instance = new library[className](dataDir);
    const worldState = new NativeWorldStateService(instance);
    await worldState.init();
    return worldState;
  }

  private async init() {
    const archive = await this.getTreeInfo(MerkleTreeId.ARCHIVE, false);
    if (archive.size === 0n) {
      const header = await this.buildInitialHeader(true);
      await this.appendLeaves(MerkleTreeId.ARCHIVE, [header.hash()]);
      await this.commit();
    }
  }

  async buildInitialHeader(ic: boolean = false): Promise<Header> {
    const state = await this.getStateReference(ic);
    return new Header(
      AppendOnlyTreeSnapshot.zero(),
      ContentCommitment.empty(),
      state,
      GlobalVariables.empty(),
      Fr.ZERO,
    );
  }

  async appendLeaves<ID extends MerkleTreeId>(treeId: ID, leaves: MerkleTreeLeafType<ID>[]): Promise<void> {
    await this.call(WorldStateMessageType.APPEND_LEAVES, {
      leaves: leaves.map(leaf => leaf as any),
      treeId,
    });
  }

  async batchInsert<TreeHeight extends number, SubtreeSiblingPathHeight extends number, ID extends IndexedTreeId>(
    treeId: ID,
    rawLeaves: Buffer[],
  ): Promise<BatchInsertionResult<TreeHeight, SubtreeSiblingPathHeight>> {
    const leaves = rawLeaves.map((leaf: Buffer) => hydrateLeaf(treeId, leaf)).map(serializeLeaf);
    const resp = await this.call(WorldStateMessageType.BATCH_INSERT, { leaves, treeId });

    return {
      newSubtreeSiblingPath: new SiblingPath<SubtreeSiblingPathHeight>(
        resp.subtree_path.length as any,
        resp.subtree_path,
      ),
      sortedNewLeaves: resp.sorted_leaves
        .map(([leaf]) => leaf)
        .map(deserializeLeafValue)
        .map(serializeToBuffer),
      sortedNewLeavesIndexes: resp.sorted_leaves.map(([, index]) => index),
      lowLeavesWitnessData: resp.low_leaf_witness_data.map(data => ({
        index: BigInt(data.index),
        leafPreimage: deserializeIndexedLeaf(data.leaf),
        siblingPath: new SiblingPath<TreeHeight>(data.path.length as any, data.path),
      })),
    };
  }

  async commit(): Promise<void> {
    await this.call(WorldStateMessageType.COMMIT, void 0);
  }

  findLeafIndex(
    treeId: MerkleTreeId,
    value: MerkleTreeLeafType<MerkleTreeId>,
    includeUncommitted: boolean,
  ): Promise<bigint | undefined> {
    return this.findLeafIndexAfter(treeId, value, 0n, includeUncommitted);
  }

  async findLeafIndexAfter(
    treeId: MerkleTreeId,
    leaf: MerkleTreeLeafType<MerkleTreeId>,
    startIndex: bigint,
    includeUncommitted: boolean,
  ): Promise<bigint | undefined> {
    const index = await this.call(WorldStateMessageType.FIND_LEAF_INDEX, {
      leaf: serializeLeaf(hydrateLeaf(treeId, leaf)),
      revision: worldStateRevision(includeUncommitted),
      treeId,
      startIndex,
    });

    if (typeof index === 'number' || typeof index === 'bigint') {
      return BigInt(index);
    } else {
      return undefined;
    }
  }

  async getLeafPreimage(
    treeId: IndexedTreeId,
    leafIndex: bigint,
    args: boolean,
  ): Promise<IndexedTreeLeafPreimage | undefined> {
    const resp = await this.call(WorldStateMessageType.GET_LEAF_PREIMAGE, {
      leafIndex,
      revision: worldStateRevision(args),
      treeId,
    });

    return resp ? deserializeIndexedLeaf(resp) : undefined;
  }

  async getLeafValue(
    treeId: MerkleTreeId,
    leafIndex: bigint,
    includeUncommitted: boolean,
  ): Promise<MerkleTreeLeafType<MerkleTreeId> | undefined> {
    const resp = await this.call(WorldStateMessageType.GET_LEAF_VALUE, {
      leafIndex,
      revision: worldStateRevision(includeUncommitted),
      treeId,
    });

    if (!resp) {
      return undefined;
    }

    const leaf = deserializeLeafValue(resp);
    if (leaf instanceof Fr) {
      return leaf;
    } else {
      return leaf.toBuffer();
    }
  }

  async getPreviousValueIndex(
    treeId: IndexedTreeId,
    value: bigint,
    includeUncommitted: boolean,
  ): Promise<{ index: bigint; alreadyPresent: boolean } | undefined> {
    const resp = await this.call(WorldStateMessageType.FIND_LOW_LEAF, {
      key: new Fr(value),
      revision: worldStateRevision(includeUncommitted),
      treeId,
    });
    return {
      alreadyPresent: resp.alreadyPresent,
      index: BigInt(resp.index),
    };
  }

  async getSiblingPath(
    treeId: MerkleTreeId,
    leafIndex: bigint,
    includeUncommitted: boolean,
  ): Promise<SiblingPath<number>> {
    const siblingPath = await this.call(WorldStateMessageType.GET_SIBLING_PATH, {
      leafIndex,
      revision: worldStateRevision(includeUncommitted),
      treeId,
    });

    return new SiblingPath(siblingPath.length, siblingPath);
  }

  getSnapshot(block: number): Promise<TreeSnapshots> {
    return Promise.reject(new Error('Method not implemented'));
  }

  async getStateReference(includeUncommitted: boolean): Promise<StateReference> {
    const resp = await this.call(WorldStateMessageType.GET_STATE_REFERENCE, {
      revision: worldStateRevision(includeUncommitted),
    });

    return new StateReference(
      treeStateReferenceToSnapshot(resp.state[MerkleTreeId.L1_TO_L2_MESSAGE_TREE]),
      new PartialStateReference(
        treeStateReferenceToSnapshot(resp.state[MerkleTreeId.NOTE_HASH_TREE]),
        treeStateReferenceToSnapshot(resp.state[MerkleTreeId.NULLIFIER_TREE]),
        treeStateReferenceToSnapshot(resp.state[MerkleTreeId.PUBLIC_DATA_TREE]),
      ),
    );
  }

  async getTreeInfo(treeId: MerkleTreeId, includeUncommitted: boolean): Promise<TreeInfo> {
    const resp = await this.call(WorldStateMessageType.GET_TREE_INFO, {
      treeId: treeId,
      revision: worldStateRevision(includeUncommitted),
    });

    return {
      depth: resp.depth,
      root: resp.root,
      size: BigInt(resp.size),
      treeId,
    };
  }

  async handleL2BlockAndMessages(l2Block: L2Block, l1ToL2Messages: Fr[]): Promise<HandleL2BlockAndMessagesResult> {
    // We have to pad both the tx effects and the values within tx effects because that's how the trees are built
    // by circuits.
    const paddedTxEffects = padArrayEnd(
      l2Block.body.txEffects,
      TxEffect.empty(),
      l2Block.body.numberOfTxsIncludingPadded,
    );

    const paddedNoteHashes = paddedTxEffects.flatMap(txEffect =>
      padArrayEnd(txEffect.noteHashes, Fr.ZERO, MAX_NEW_NOTE_HASHES_PER_TX),
    );
    const paddedL1ToL2Messages = padArrayEnd(l1ToL2Messages, Fr.ZERO, NUMBER_OF_L1_L2_MESSAGES_PER_ROLLUP);

    const paddedNullifiers = paddedTxEffects
      .flatMap(txEffect => padArrayEnd(txEffect.nullifiers, Fr.ZERO, MAX_NEW_NULLIFIERS_PER_TX))
      .map(nullifier => new NullifierLeaf(nullifier));
    // We insert the public data tree leaves with one batch per tx to avoid updating the same key twice

    const batchesOfPaddedPublicDataWrites: PublicDataTreeLeaf[][] = [];
    for (const txEffect of paddedTxEffects) {
      const batch: PublicDataTreeLeaf[] = Array(MAX_TOTAL_PUBLIC_DATA_UPDATE_REQUESTS_PER_TX).fill(
        PublicDataTreeLeaf.empty(),
      );
      for (const [i, write] of txEffect.publicDataWrites.entries()) {
        batch[i] = new PublicDataTreeLeaf(write.leafIndex, write.newValue);
      }

      batchesOfPaddedPublicDataWrites.push(batch);
    }

    return await this.call(WorldStateMessageType.SYNC_BLOCK, {
      blockHash: l2Block.hash(),
      paddedL1ToL2Messages,
      paddedNoteHashes,
      paddedNullifiers,
      batchesOfPaddedPublicDataWrites,
      blockStateRef: l2Block.header.state,
    });
  }

  async rollback(): Promise<void> {
    await this.call(WorldStateMessageType.ROLLBACK, void 0);
  }

  async updateArchive(header: Header, args: boolean): Promise<void> {
    throw new Error('not implemented');
  }

  async updateLeaf<ID extends IndexedTreeId>(
    treeId: ID,
    leaf: NullifierLeafPreimage | Buffer,
    index: bigint,
  ): Promise<void> {
    throw new Error('Method not implemented');
  }

  private async call<T extends WorldStateMessageType>(
    messageType: T,
    body: WorldStateRequest[T],
  ): Promise<WorldStateResponse[T]> {
    const message = new TypedMessage(messageType, new MessageHeader({ messageId: this.nextMessageId++ }), body);

    const encodedRequest = this.encoder.encode(message);
    const encodedResponse = await this.instance.call(encodedRequest);

    console.log({
      message,
      encodedResponse,
    });

    if (typeof encodedResponse === 'undefined') {
      throw new Error('Empty response from native library');
    }

    const buf = Buffer.isBuffer(encodedResponse)
      ? encodedResponse
      : isAnyArrayBuffer(encodedResponse)
      ? Buffer.from(encodedResponse)
      : undefined;

    if (!buf) {
      throw new Error(
        'Invalid response from native library: expected Buffer or ArrayBuffer, got ' + typeof encodedResponse,
      );
    }

    const response = TypedMessage.fromMessagePack<T, WorldStateResponse[T]>(this.decoder.unpack(buf));

    if (response.header.requestId !== message.header.messageId) {
      throw new Error(
        'Response ID does not match request: ' + response.header.requestId + ' != ' + message.header.messageId,
      );
    }

    return response.value;
  }
}

function hydrateLeaf<ID extends MerkleTreeId>(treeId: ID, leaf: MerkleTreeLeafType<ID>) {
  if (leaf instanceof Fr) {
    return leaf as Fr;
  } else if (treeId === MerkleTreeId.NULLIFIER_TREE) {
    return NullifierLeaf.fromBuffer(leaf);
  } else if (treeId === MerkleTreeId.PUBLIC_DATA_TREE) {
    return PublicDataTreeLeaf.fromBuffer(leaf);
  } else {
    throw new Error('Invalid leaf type');
  }
}

function serializeLeaf(leaf: Fr | NullifierLeaf | PublicDataTreeLeaf): SerializedLeafValue {
  if (leaf instanceof Fr) {
    return leaf.toBuffer();
  } else if (leaf instanceof NullifierLeaf) {
    return { value: leaf.nullifier.toBuffer() };
  } else {
    return { value: leaf.value.toBuffer(), slot: leaf.slot.toBuffer() };
  }
}

function deserializeLeafValue(leaf: SerializedLeafValue): Fr | NullifierLeaf | PublicDataTreeLeaf {
  if (Buffer.isBuffer(leaf)) {
    return Fr.fromBuffer(leaf);
  } else if ('slot' in leaf) {
    return new PublicDataTreeLeaf(Fr.fromBuffer(leaf.slot), Fr.fromBuffer(leaf.value));
  } else {
    return new NullifierLeaf(Fr.fromBuffer(leaf.value));
  }
}

function deserializeIndexedLeaf(leaf: SerializedIndexedLeaf): IndexedTreeLeafPreimage {
  if ('slot' in leaf.value) {
    return new PublicDataTreeLeafPreimage(
      Fr.fromBuffer(leaf.value.slot),
      Fr.fromBuffer(leaf.value.value),
      Fr.fromBuffer(leaf.nextValue),
      BigInt(leaf.nextIndex),
    );
  } else if ('value' in leaf.value) {
    return new NullifierLeafPreimage(
      Fr.fromBuffer(leaf.value.value),
      Fr.fromBuffer(leaf.nextValue),
      BigInt(leaf.nextIndex),
    );
  } else {
    throw new Error('Invalid leaf type');
  }
}

import { GlobalVariables, HistoricBlockData, PublicCircuitPublicInputs } from '@aztec/circuits.js';
import { createDebugLogger } from '@aztec/foundation/log';

import { Oracle } from '../acvm/index.js';
import { ExecutionError, createSimulationError } from '../common/errors.js';
import { SideEffectCounter } from '../common/index.js';
import { PackedArgsCache } from '../common/packed_args_cache.js';
import { AcirSimulator } from '../index.js';
import { CommitmentsDB, PublicContractsDB, PublicStateDB } from './db.js';
import { PublicExecution, PublicExecutionResult } from './execution.js';
import { PublicExecutionContext } from './public_execution_context.js';
import { PublicVmExecutionContext } from './public_vm_execution_context.js';
import { Fr } from '@aztec/circuits.js';


const VM_MEM_SIZE = 1024;

enum Opcode {
  CALLDATACOPY,
  ADD,
  RETURN,
  JUMP,
  JUMPI,
}

const PC_MODIFIERS = [ Opcode.JUMP, Opcode.JUMPI ];

class AVMInstruction {
  constructor(
    public opcode: Opcode,
    public d0: number,
    public sd: number,
    public s0: number,
    public s1: number,
  ) {}
}

/**
 * Execute a public function and return the execution result.
 */
export async function executePublicFunction(
  context: PublicVmExecutionContext,
  _bytecode: Buffer,
  log = createDebugLogger('aztec:simulator:public_execution'),
): Promise<PublicExecutionResult> {
  let bytecode = [
    new AVMInstruction(
      /*opcode*/ Opcode.CALLDATACOPY,
      /*d0:*/ 0, /*target memory address*/
      /*sd:*/ 0, /*unused*/
      /*s0:*/ 1, /*calldata offset*/
      /*s1:*/ 2, /*copy size*/ // M[0:0+M[2]] = CD[1+M[2]]);
    ),
  ];
  //let bytecode = [
  //  { opcode: "CALLDATACOPY", d0: 0 /*target memory address*/, s0: 1 /*calldata offset*/, s1: 2 /*copy size*/}, // M[0:0+M[2]] = CD[1+M[2]]
  //  { opcode: "ADD", d0: 10, s0: 0, s1: 0}, // M[10] = M[0] + M[0]
  //  { opcode: "RETURN", s0: 10 /*memory to return*/, s1: 1 /*size*/}, // return M[10:10+M[1]]

  //];
  const execution = context.execution;
  const { contractAddress, functionData } = execution;
  const selector = functionData.selector;
  log(`Executing public external function ${contractAddress.toString()}:${selector}`);

  // PUBLIC VM
  //const vmCallback = new Oracle(context);
  const {
    returnValues,
    newL2ToL1Msgs,
    newCommitments,
    newNullifiers,
  } = await vm.execute(bytecode, context /*, vmCallback*/);

  const { contractStorageReads, contractStorageUpdateRequests } = context.getStorageActionData();
  log(
    `Contract storage reads: ${contractStorageReads
      .map(r => r.toFriendlyJSON() + ` - sec: ${r.sideEffectCounter}`)
      .join(', ')}`,
  );

  const nestedExecutions = context.getNestedExecutions();
  const unencryptedLogs = context.getUnencryptedLogs();

  return {
    execution,
    newCommitments,
    newL2ToL1Msgs,
    newNullifiers,
    contractStorageReads,
    contractStorageUpdateRequests,
    returnValues,
    nestedExecutions,
    unencryptedLogs,
  };
}

/**
 * Handles execution of public functions.
 */
export class PublicExecutor {
  constructor(
    private readonly stateDb: PublicStateDB,
    private readonly contractsDb: PublicContractsDB,
    private readonly commitmentsDb: CommitmentsDB,
    private readonly blockData: HistoricBlockData,
  ) {}

  /**
   * Executes a public execution request.
   * @param execution - The execution to run.
   * @param globalVariables - The global variables to use.
   * @returns The result of the run plus all nested runs.
   */
  public async simulate(execution: PublicExecution, globalVariables: GlobalVariables): Promise<PublicExecutionResult> {
    const selector = execution.functionData.selector;
    const acir = await this.contractsDb.getBytecode(execution.contractAddress, selector);
    if (!acir) throw new Error(`Bytecode not found for ${execution.contractAddress}:${selector}`);

    // Functions can request to pack arguments before calling other functions.
    // We use this cache to hold the packed arguments.
    const packedArgs = await PackedArgsCache.create([]);

    const sideEffectCounter = new SideEffectCounter();

    const context = new PublicVmExecutionContext(
      execution,
    );
    //const context = new PublicExecutionContext(
    //  execution,
    //  this.blockData,
    //  globalVariables,
    //  packedArgs,
    //  sideEffectCounter,
    //  this.stateDb,
    //  this.contractsDb,
    //  this.commitmentsDb,
    //);

    try {
      return await executePublicFunction(context, acir);
    } catch (err) {
      throw createSimulationError(err instanceof Error ? err : new Error('Unknown error during public execution'));
    }
  }

  public async execute(bytecode: AVMInstruction[]/*Buffer*/,
                       context: PublicVmExecutionContext,
                       /*callback: any/*Oracle*/): Promise<PublicCircuitPublicInputs> {

    let pc = 0; // TODO: should be u32
    while(pc < bytecode.length) {
      const instr = bytecode[pc];
      switch (instr.opcode) {
        case Opcode.CALLDATACOPY: {
          const srcOffset = context.fieldMem[instr.s0];
          const copySize = context.fieldMem[instr.s1];
          const dstOffset = context.fieldMem[instr.d0];
          //assert srcOffset + copySize <= context.calldata.length;
          //assert dstOffset + copySize <= context.fieldMem.length;
          for (let i = 0; i < copySize; i++) {
            context.fieldMem[dstOffset+i] = context.calldata[srcOffset+i];
          }
          break;
        }
        case Opcode.ADD: {
          context.fieldMem[instr.d0] = context.fieldMem[instr.s0] + context.fieldMem[instr.s1];
          break;
        }
        case Opcode.JUMP: {
          pc = instr.s0;
          break;
        }
        case Opcode.JUMPI: {
          pc = context.fieldMem[instr.sd] ? instr.s0 : pc + 1;
          break;
        }
        case Opcode.RETURN: {
          const srcOffset = context.fieldMem[instr.s0];
          const retSize = context.fieldMem[instr.s1];
          const endOffset = srcOffset + retSize;
          //assert srcOffset + retSize <= context.fieldMem.length;
          //assert endOffset + retSize <= context.fieldMem.length;
          return context.fieldMem.slice(srcOffset, endOffset);
        }
      }
      if (!PC_MODIFIERS.includes(instr.opcode)) {
        pc++;
      }
    }
    throw new Error("Reached end of bytecode without RETURN or REVERT");
  }

  //public async generateWitness(execution: PublicExecution, globalVariables: GlobalVariables): Promise<PublicVMWitness>;
  //public async prove(witness: PublicVMWitness) Promise<PublicExecutionResult>;
}

import {
  type AccountWallet,
  type AztecAddress, type FeePaymentMethod,
  type FunctionCall, type Wallet
} from '@aztec/aztec.js';
import { Fr, type GasSettings } from '@aztec/circuits.js';
import { FunctionSelector, FunctionType } from '@aztec/foundation/abi';
import { poseidon2Hash } from '@aztec/foundation/crypto';
import { type PrivateFPCContract, TokenWithRefundsContract } from '@aztec/noir-contracts.js';

import { FeesTest } from './fees_test.js';

describe('e2e_fees/private_refunds', () => {
  let aliceWallet: AccountWallet;
  let aliceAddress: AztecAddress;
  let bobAddress: AztecAddress;
  let tokenWithRefunds: TokenWithRefundsContract;
  let privateFPC: PrivateFPCContract;

  let initialAliceBalance: bigint;
  // Bob is the admin of the fee paying contract
  let initialBobBalance: bigint;
  let initialFPCGasBalance: bigint;

  const t = new FeesTest('private_refunds');

  beforeAll(async () => {
    await t.applyInitialAccountsSnapshot();
    await t.applyPublicDeployAccountsSnapshot();
    await t.applyDeployFeeJuiceSnapshot();
    await t.applyTokenWithRefundsAndFPC();
    await t.applyFundAliceWithTokens();
    ({ aliceWallet, aliceAddress, bobAddress, privateFPC, tokenWithRefunds } = await t.setup());
    t.logger.debug(`Alice address: ${aliceAddress}`);

    // We give Alice access to Bob's notes because Alice is used to check if balances are correct.
    aliceWallet.setScopes([aliceAddress, bobAddress]);
  });

  afterAll(async () => {
    await t.teardown();
  });

  beforeEach(async () => {
    [[initialAliceBalance, initialBobBalance], [initialFPCGasBalance]] = await Promise.all([
      t.getTokenWithRefundsBalanceFn(aliceAddress, t.bobAddress),
      t.getGasBalanceFn(privateFPC.address),
    ]);
  });

  // TODO(#7694): Remove this test once the lacking feature in TXE is implemented.
  it.only('insufficient funded amount is correctly handled', async () => {
    // 1. We generate randomness for Alice and derive randomness for Bob.
    const aliceRandomness = Fr.random(); // Called user_randomness in contracts
    const bobRandomness = poseidon2Hash([aliceRandomness]); // Called fee_payer_randomness in contracts

    // 2. We call arbitrary `private_get_name(...)` function to check that the fee refund flow works.
      await expect(
        tokenWithRefunds.methods.private_get_name().prove({
          fee: {
            gasSettings: t.gasSettings,
            paymentMethod: new PrivateRefundPaymentMethod(
              tokenWithRefunds.address,
              privateFPC.address,
              aliceWallet,
              aliceRandomness,
              bobRandomness,
              t.bobWallet.getAddress(), // Bob is the recipient of the fee notes.
              true, // We set max fee/funded amount to zero to trigger the error.
            ),
          },
        }),
      ).rejects.toThrow('funded amount not enough to cover tx fee');
    });

  //   await expect(
  //     tokenWithRefunds.methods
  //       .setup_refund(bobAddress, aliceAddress, 4, aliceRandomness, bobRandomness)
  //       .prove(),
  //   ).rejects.toThrow('funded amount not enough to cover tx fee');
  // });
});

class PrivateRefundPaymentMethod implements FeePaymentMethod {
  constructor(
    /**
     * The asset used to pay the fee.
     */
    private asset: AztecAddress,
    /**
     * Address which will hold the fee payment.
     */
    private paymentContract: AztecAddress,

    /**
     * An auth witness provider to authorize fee payments
     */
    private wallet: Wallet,

    /**
     * A randomness to mix in with the generated refund note for the sponsored user.
     * Use this to reconstruct note preimages for the PXE.
     */
    private userRandomness: Fr,

    /**
     * A randomness to mix in with the generated fee note for the fee payer.
     * Use this to reconstruct note preimages for the PXE.
     */
    private feePayerRandomness: Fr,

    /**
     * Address that the FPC sends notes it receives to.
     */
    private feeRecipient: AztecAddress,

    /**
     * If true, the max fee will be set to 0.
     * TODO(#7694): Remove this param once the lacking feature in TXE is implemented.
     */
    private setMaxFeeToZero = false,
  ) {}

  /**
   * The asset used to pay the fee.
   * @returns The asset used to pay the fee.
   */
  getAsset() {
    return this.asset;
  }

  getFeePayer(): Promise<AztecAddress> {
    return Promise.resolve(this.paymentContract);
  }

  /**
   * Creates a function call to pay the fee in the given asset.
   * @param gasSettings - The gas settings.
   * @returns The function call to pay the fee.
   */
  async getFunctionCalls(gasSettings: GasSettings): Promise<FunctionCall[]> {
    // We assume 1:1 exchange rate between fee juice and token. But in reality you would need to convert feeLimit
    // (maxFee) to be in token denomination.
    const maxFee = this.setMaxFeeToZero ? Fr.ZERO : gasSettings.getFeeLimit();

    await this.wallet.createAuthWit({
      caller: this.paymentContract,
      action: {
        name: 'setup_refund',
        args: [
          this.feeRecipient,
          this.wallet.getCompleteAddress().address,
          maxFee,
          this.userRandomness,
          this.feePayerRandomness,
        ],
        selector: FunctionSelector.fromSignature('setup_refund((Field),(Field),Field,Field,Field)'),
        type: FunctionType.PRIVATE,
        isStatic: false,
        to: this.asset,
        returnTypes: [],
      },
    });

    return [
      {
        name: 'fund_transaction_privately',
        to: this.paymentContract,
        selector: FunctionSelector.fromSignature('fund_transaction_privately(Field,(Field),Field)'),
        type: FunctionType.PRIVATE,
        isStatic: false,
        args: [maxFee, this.asset, this.userRandomness],
        returnTypes: [],
      },
    ];
  }
}

import { createCompatibleClient } from '@aztec/aztec.js';
import { AztecAddress } from '@aztec/circuits.js';
import { FeeJuicePortalManager, prettyPrintJSON } from '@aztec/cli/utils';
import { createEthereumChain, createL1Clients } from '@aztec/ethereum';
import { type DebugLogger, type LogFn } from '@aztec/foundation/log';

export async function bridgeL1FeeJuice(
  amount: bigint,
  recipient: AztecAddress,
  rpcUrl: string,
  l1RpcUrl: string,
  chainId: number,
  privateKey: string | undefined,
  mnemonic: string,
  mint: boolean,
  json: boolean,
  log: LogFn,
  debugLogger: DebugLogger,
) {
  // Prepare L1 client
  const chain = createEthereumChain(l1RpcUrl, chainId);
  const { publicClient, walletClient } = createL1Clients(chain.rpcUrl, privateKey ?? mnemonic, chain.chainInfo);

  // Prepare L2 client
  const client = await createCompatibleClient(rpcUrl, debugLogger);

  // Setup portal manager
  const portal = await FeeJuicePortalManager.create(client, publicClient, walletClient, debugLogger);
  const { secret, msgHash } = await portal.prepareTokensOnL1(amount, amount, recipient, mint);

  const l2TokenAddress = AztecAddress.fromString(await portal.getPortalContract().read.l2TokenAddress());

  if (json) {
    const out = {
      claimAmount: amount,
      claimSecret: secret,
    };
    log(prettyPrintJSON(out));
  } else {
    if (mint) {
      log(`Minted ${amount} fee juice on L1 and pushed to L2 portal`);
    } else {
      log(`Bridged ${amount} fee juice to L2 portal`);
    }
    log(`claimAmount=${amount},claimSecret=${secret},contractAddress=${l2TokenAddress},msgHash=${msgHash}\n`);
    log(`Note: You need to wait for two L2 blocks before pulling them from the L2 side`);
    log(`This command will now continually poll every minute for the inclusion of the newly created L1 to L2 message`);
  }

  const recheck = setInterval(async () => {
    const l1ToL2MembershipWitness = await client.getL1ToL2MembershipWitness(l2TokenAddress, msgHash, secret);
    if (l1ToL2MembershipWitness) {
      log(`Successfully retrieved L1 to L2 message. Index: ${l1ToL2MembershipWitness[0]}`);
      clearInterval(recheck);
    }
  }, 60_000);

  return secret;
}

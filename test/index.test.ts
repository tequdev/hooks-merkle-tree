import { SetHookFlags, Wallet, calculateHookOn, decodeAccountID, hexHookParameters } from '@transia/xrpl'

import Sha512Half from "@transia/xrpl/dist/npm/utils/hashes/sha512Half";

import {
  serverUrl,
  XrplIntegrationTestContext,
  setupClient,
  teardownClient,
} from '@transia/hooks-toolkit/dist/npm/src/libs/xrpl-helpers'

import {
  ALICE_WALLET, BOB_WALLET, CAROL_WALLET, DAVE_WALLET, ELSA_WALLET, FRANK_WALLET, GRACE_WALLET, HEIDI_WALLET
} from '@transia/hooks-toolkit/dist/npm/src/libs/xrpl-helpers/constants'

import {
  SetHookParams,
  setHooksV3,
  hexNamespace,
  iHook,
  readHookBinaryHexFromNS,
  clearAllHooksV3,
  clearHookStateV3,
  Xrpld,
} from '@transia/hooks-toolkit'

const namespace = 'namespace'

const toHash = (data: string) => Sha512Half(data.toUpperCase()).toUpperCase()

const toHexData = (wallet: Wallet, data: string) => decodeAccountID(wallet.address).toString('hex').toUpperCase() + data.toUpperCase()

const proof = {
  0: toHash(toHexData(ALICE_WALLET, '')),
  1: toHash(toHexData(BOB_WALLET, '')),
  2: toHash(toHexData(CAROL_WALLET, '')),
  3: toHash(toHexData(DAVE_WALLET, '')),
  4: toHash(toHexData(ELSA_WALLET, '')),
  5: toHash(toHexData(FRANK_WALLET, '')),
  6: toHash(toHexData(GRACE_WALLET, '')),
  7: toHash(toHexData(HEIDI_WALLET, '')),
}

const proof01 = toHash(proof['0'] + proof['1'])
const proof23 = toHash(proof['2'] + proof['3'])
const proof45 = toHash(proof['4'] + proof['5'])
const proof67 = toHash(proof['6'] + proof['7'])
const proof0123 = toHash(proof01 + proof23)
const proof4567 = toHash(proof45 + proof67)

const root = toHash(proof0123 + proof4567)

describe('test', () => {
  let testContext: XrplIntegrationTestContext

  beforeAll(async () => {
    testContext = await setupClient(serverUrl)
    const hook = {
      CreateCode: readHookBinaryHexFromNS('../build/index'),
      Flags: SetHookFlags.hsfOverride,
      HookOn: calculateHookOn(['Invoke']),
      HookNamespace: hexNamespace(namespace),
      HookApiVersion: 0,
      HookParameters: hexHookParameters([{
        HookParameter: {
          HookParameterName: 'RT',
          HookParameterValue: root
        }
      }])
    } as iHook
    await setHooksV3({
      client: testContext.client,
      seed: testContext.alice.seed,
      hooks: [{ Hook: hook }],
    } as SetHookParams)
  })

  afterAll(async () => {
    const clearHook = {
      Flags: SetHookFlags.hsfNSDelete,
      HookNamespace: hexNamespace(namespace),
    } as iHook
    await clearHookStateV3({
      client: testContext.client,
      seed: testContext.alice.seed,
      hooks: [{ Hook: clearHook }],
    } as SetHookParams)
    await clearAllHooksV3({
      client: testContext.client,
      seed: testContext.alice.seed,
    } as SetHookParams)
    await teardownClient(testContext)
  })

  it('Valid Proof', async () => {
    // index: 0
    await Xrpld.submit(testContext.client, {
      tx: {
        TransactionType: 'Invoke',
        Account: testContext.alice.address,
        Blob: proof['1'] + proof23 + proof4567 + toHexData(ALICE_WALLET, "") + "00"
      },
      wallet: testContext.alice
    })
    await Xrpld.submit(testContext.client, {
      tx: {
        TransactionType: 'Invoke',
        Account: testContext.alice.address,
        Blob: proof['0'] + proof23 + proof4567 + toHexData(BOB_WALLET, "") + "01"
      },
      wallet: testContext.alice
    })
  })

  it('Invalid Proof', async () => {
    // index: 0
    {
      const result = Xrpld.submit(testContext.client, {
        tx: {
          TransactionType: 'Invoke',
          Account: testContext.alice.address,
          Blob: proof['1'] + proof23 + proof4567 + toHexData(BOB_WALLET, "") + "00"
        },
        wallet: testContext.alice
      })
      await expect(result).rejects.toThrow()
    }
    {
      const result = Xrpld.submit(testContext.client, {
        tx: {
          TransactionType: 'Invoke',
          Account: testContext.alice.address,
          Blob: proof['1'] + proof23 + proof4567 + toHexData(ALICE_WALLET, "") + "01"
        },
        wallet: testContext.alice
      })
      await expect(result).rejects.toThrow()
    }
  })
})

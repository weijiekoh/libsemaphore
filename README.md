# A Semaphore and MicroMix client library

This repository contains the code necessary for third-party developers to
easily integrate Semaphore, a zero-knowledge signalling gadget, or MicroMix, a
mixer built upon Semaphore.

## About Semaphore

Semaphore is a set of Solidity contracts and zk-SNARK
[`circom`](https://github.com/iden3/circom) circuits. It allows any Ethereum
developer to build client application that offer a specific form of privacy:
the ability to anonymously prove membership of a set of identities, while
broadcasting an arbitary string (also known as a signal). Each identity can
only broadcast once per *external nullifier*. Semaphore supports multiple
external nullifiers.

Each client application must use the above features of Semaphore in a unique
way to achieve its privacy goals. MicroMix, for instance, is configured as
such:

| Signal | External nullifier |
|-|-|
| The hash of the recipient's address, relayer's address, and the relayer's fee | The MicroMix contract address |

This allows anonymous withdrawals of funds (via a transaction relayer, who is
rewarded with a fee), and prevents double-spending as there is only one
external nullifier.

An anonymous voting app would be configured differently:

| Signal | External nullifier |
|-|-|
| The hash of the respondent's answer | The hash of the question |

This allows any user to vote with an arbitary response (e.g. yes, no, or maybe)
to any question. The user, however, can only vote once per question.

## Using libsemaphore to build a mixer

We refer below to any third-party app, like a mixer user interface, as a
*client*.

To use the mixer, each client must be able to:

1. Given a desired denomination and amount to mix (e.g. 10 DAI or 1 ETH),
   determine the correct Mixer contract.

2. Generate and store an `Identity` (which contains an `EddsaKeyPair`, identity
   nullifier, and identity trapdoor).

   ```ts
   import {
       // function, type, or interface name here
   } from 'libsemaphore'
   ```

   ```ts
   const identity: Identity = genIdentity()
   ```

3. Generate and store an identity commitment using the items above data.

    ```ts
    const identityCommitment = genIdentityCommitment(identity)
    ```

4. Perform an Ethereum transaction containing the identity commitment as data
   to the desired Mixer contract's `deposit` or `depositERC20` function.

5. Download or load from disk a proving key and circuit file.

    To load a circuit from disk, use:

    ```ts
    const cirDef = JSON.parse(fs.readFileSync(PATH_TO_CIRCUIT).toString())
    ```

    Likewise, to load a proving key from disk: use:

    ```ts
    const provingKey = fs.readFileSync(PATH_TO_PROVING_KEY)
    ```

    To download a circuit, use:

    ```ts
    const cirDef = await (await fetchWithoutCache(CIRCUIT_URL)).json() 
    const circuit = genCircuit(cirDef)
    ```

    Where `fetchWithoutCache` is defined as such to instruct the user's web
    browser to not cache the circuit, which may cause errors during witness
    generation:

    ```ts
    const fetchWithoutCache = (
        url: string,
    ) => {
        return fetch( url, { cache: "no-store" })
    }
    ```

    To download a proving key, use:

    ```ts
    const provingKey = new Uint8Array(
        await (await fetch(PROVING_KEY_URL)).arrayBuffer()
    )
    ```

6. Retrieve a list of leaves from the Mixer contract using its `getLeaves()`
   view function.

7. Decide on a relayer to which to send a withdrawal transaction.

8. Generate the signal tailored for the mixer and the zk-SNARK witness. This
   step will fail if these inputs are invalid.

   The default tree depth is 20, and the leaves come from the Mixer contract's
   `getLeaves()` function.

    ```ts
    const circuit = genCircuit(cirDef)

    const signal = genMixerSignal(
        recipientAddress,
        broadcasterAddress,
        feeAmt,
    )

    const result = await genWitness(
        signal,
        circuit,
        identity,
        LEAVES,
        TREE_DEPTH,
        externalNullifier,
    )

    witness = result.witness
    ```

9. Generate a *proof* using `w` and the proving key.

    ```ts
    const proof = await genProof(witness, provingKey)
    const publicSignals = genPublicSignals(witness, circuit)
    ```

10. Optionally download a verification key and use it to verify the proof before
   sending it to the Mixer contract.

   - To load the verifying key, which is a JSON file, note that all numeric
     values in it are represented by strings. A convenience function to
     un-stringify and parse the JSON is libsemaphore's
     `parseVerifyingKeyJson(verifyingKeyAsText)`.

        ```ts
        // remember to import the fs module: import * as fs from 'fs'
        const verifyingKey = parseVerifyingKeyJson(fs.readFileSync(verifyingKeyPath).toString())
        ```

   - To verify the proof off-chain, use the `verifyProof()` function.

        ```ts
        const isValid = verifyProof(verifyingKey, proof, publicSignals)
        ```

11. Send the proof, recipient's address, fee, and relayers address, along with
    to the Mixer contract's `mix` or `mixERC20` function, via a relayer. The
    following code snippet, however, will demonstrate how to invoke the mixer
    contract directly, assuming that `mixerContract` is an `ethers.Contract`
    instance.

    ```ts
    const formatted = formatForVerifierContract(proof, publicSignals)
    const tx = await mixerContract.mix(
        {
            signal,
            formatted.a,
            formatted.b,
            formatted.c,
            formatted.input,
            recipientAddress,
            fee,
        },
        forwarderAddress,
    )
    ```

## Using libsemaphore to build other applications

Other applications of Semaphore, like private DAOs or anonymous login, use the
Semaphore contract differently than MicroMix. The steps to generate an identity
and identity commitment, however, remain the same. The identity commitment
should be sent to Semaphore's `insertIdentity()` contract function.

You can generate a witness with any arbitary signal using the `genWitness(...)`
function. See below for the required parameters.

## Available types, interfaces, and functions

### Types

**`SnarkBigInt`**

Encapsulates `snarkjs.bigInt`.

**`EddsaPrivateKey`**

An [EdDSA](https://tools.ietf.org/html/rfc8032) private key which should be 32
bytes long.

Encapsulates a [`Buffer`](https://nodejs.org/api/buffer.html).

**`EddsaPublicKey`**

An EdDSA public key. Encapsulates an array of `SnarkBigInt`s.

**`SnarkProvingKey`**

A proving key, which when used with a secret *witness*, generates a zk-SNARK
proof about said witness. Encapsulates a `Buffer`.

**`SnarkVerifyingKey`**

A verifying key which when used with public inputs to a zk-SNARK and a
`SnarkProof`, can prove the proof's validity. Encapsulates a `Buffer`.

**`SnarkWitness`**

The secret inputs to a zk-SNARK. Encapsulates an array of `SnarkBigInt`s.

**`SnarkPublicSignals`**

The public inputs to a zk-SNARK. Encapsulates an array of `SnarkBigInt`s.

### Interfaces

**`EddsaKeyPair`**

Encapsulates an `EddsaPublicKey` and an `EddsaPrivateKey`.

```ts
interface EddsaKeyPair {
    pubKey: EddsaPublicKey,
    privKey: EddsaPrivateKey,
 }
```

**`Identity`**

Encapsulates all information required to generate an identity commitment, and
is crucial to creating `SnarkProof`s to broadcast signals in Semaphore or
perform mixer withdrawals.

```ts
interface Identity {
    keypair: EddsaKeyPair,
    identityNullifier: SnarkBigInt,
    identityTrapdoor: SnarkBigInt,
}
```

**`SnarkProof`**

Encapsulates zk-SNARK proof data required by `verifyProof()`.

```ts
interface SnarkProof {
    pi_a: SnarkBigInt[]
    pi_b: SnarkBigInt[][]
    pi_c: SnarkBigInt[]
}
```

### Functions

**`genPubKey(privKey: EddsaPrivateKey): EddsaPublicKey`**

Generates a public EdDSA key from a supplied private key. To generate a private
key, use `crypto.randomBytes(32)` where `crypto` is the built-in Node or
browser module.

**`genIdentity(): Identity`**

This is a convenience function to generate a fresh and random `Identity`. That
is, the 32-byte private key for the `EddsaKeyPair` is randomly generated, as
are the distinct 31-byte identity nullifier and the 31-byte identity trapdoor
values.

**`serialiseIdentity(identity: Identity): string`**

Converts an `Identity` into a JSON string which looks like this:

```text
["e82cc2b8654705e427df423c6300307a873a2e637028fab3163cf95b18bb172e","a02e517dfb3a4184adaa951d02bfe0fe092d1ee34438721d798db75b8db083","15c6540bf7bddb0616984fccda7e954a0fb5ea4679ac686509dc4bd7ba9c3b"]
```

You can also spell this function as `serializeIdentity`.

To convert this string back into an `Identity`, use `unSerialiseIdentity()`.

**`unSerialiseIdentity(string: serialisedId): Identity`**

Converts the `string` output of `serialiseIdentity()` to an `Identity`.

You can also spell this function as `unSerializeIdentity`.

**`genIdentityCommitment(identity: Identity): SnarkBigInt`**

Generates an identity commitment, which is the hash of the public key, the
identity nullifier, and the identity trapdoor.

**`async genProof(witness: SnarkWitness, provingKey: SnarkProvingKey): SnarkProof`**

Generates a `SnarkProof`, which can be sent to the Semaphore contract's
`broadcastSignal()` function, or the Mixer's `mix()` or `mixERC20` functions.
It can also be verified off-chain using `verifyProof()` below.

**`genPublicSignals(witness: SnarkWitness, circuit: SnarkCircuit): SnarkPublicSignals`**

Extracts the public signals to be supplied to the contract or `verifyProof()`.

**`verifyProof(verifyingKey: SnarkVerifyingKey, proof: SnarkProof, publicSignals: SnarkPublicSignals): boolean`**

Returns `true` if the given `proof` is valid, given the correct verifying key
and public signals.

Returns `false` otherwise.

**`signMsg(privKey: EddsaPrivateKey, msg: SnarkBigInt): EdDSAMiMcSpongeSignature)`**

Encapsualtes `circomlib.eddsa.signMiMCSponge` to sign a message `msg` using private key `privKey`.

**`verifySignature(msg: SnarkBigInt, signature: EdDSAMiMcSpongeSignature, pubKey: EddsaPublicKey)`: boolean**

Returns `true` if the cryptographic `signature` of the signed `msg` is from the
private key associated with `pubKey`.

Returns `false` otherwise.

**`setupTree(levels: number, prefix: string): MerkleTree`**

Returns a Merkle tree created using
[`semaphore-merkle-tree`](https://www.npmjs.com/package/semaphore-merkle-tree)
with the same number of levels which the Semaphore zk-SNARK circuit expects.
This tree is also configured to use `MimcSpongeHasher`, which is also what the
circuit expects.

`levels` sets the number of levels of the tree. A tree with 20 levels, for
instance, supports up to 1048576 deposits.

**`genCircuit(circuitDefinition: any)`**

Returns a `new snarkjs.Circuit(circuitDefinition)`. The `circuitDefinition`
object should be the `JSON.parse`d result of the `circom` command which
converts a `.circom` file to a `.json` file.

**`async genWitness(...)`**

This function has the following signature:

```ts
const genWitness = async (
    signal: string,
    circuit: SnarkCircuit,
    identity: Identity,
    idCommitments: SnarkBigInt[] | BigInt[] | ethers.utils.BigNumber[],
    treeDepth: number,
    externalNullifier: SnarkBigInt,
)
```

- `signal` is the string you wish to broadcast.
- `circuit` is the output of `genCircuit()`.
- `identity` is the `Identity` whose identity commitment you want to prove is
  in the set of registered identities.
- `idCommitments` is an array of registered identity commmitments; i.e. the
  leaves of the tree.
- `treeDepth` is the number of levels which the Merkle tree used has
- `externalNullifier` is the current external nullifier

It returns an object as such:

- `witness`: The witness to pass to `genProof()`.
- `signal`: The computed signal for Semaphore. This is the hash of the
  recipient's address, relayer's address, and fee.
- `signalHash`: The hash of the computed signal.
- `msg`: The hash of the external nullifier and the signal hash
- `signature`: The signature on the above msg.
- `tree`: The Merkle tree object after it has been updated with the identity commitment
- `identityPath`: The Merkle path to the identity commmitment
- `identityPathIndex`: The leaf index of the identity commitment
- `identityPathElements`: The elements along the above Merkle path

Only `witness` is essential to generate the proof; the other data is only
useful for debugging and additional off-chain checks, such as verifying the
signature and the Merkle tree root.

**`formatForVerifierContract = (proof: SnarkProof, publicSignals: SnarkPublicSignals`**

Converts the data in `proof` and `publicSignals` to strings and rearranges
elements of `proof.pi_b` so that `snarkjs`'s `verifier.sol` will accept it.
To be specific, it returns an object as such:

```ts
{
    a: [ proof.pi_a[0].toString(), proof.pi_a[1].toString() ],
    b: [ 
         [ proof.pi_b[0][1].toString(), proof.pi_b[0][0].toString() ],
         [ proof.pi_b[1][1].toString(), proof.pi_b[1][0].toString() ],
    ],
    c: [ proof.pi_c[0].toString(), proof.pi_c[1].toString() ],
    input: publicSignals.map((x) => x.toString()),
}
```

**`stringifyBigInts = (obj: any) => object`**

Encapsulates `snarkjs.stringifyBigInts()`. Makes it easy to convert `SnarkProof`s to JSON. 

**`unstringifyBigInts = (obj: any) => object`**

Encapsulates `snarkjs.unstringifyBigInts()`. Makes it easy to convert JSON to `SnarkProof`s.

**`genExternalNullifier = (plaintext: string) => string`**

Each external nullifier must be at most 29 bytes large. This function
keccak-256-hashes a given `plaintext`, takes the last 29 bytes, and pads it
(from the start) with 0s, and returns the resulting hex string.

### Mixer-specific functions 

**`async genMixerWitness(...)`**

This function has the following signature:

```ts:
const genMixerWitness = (
    circuit: SnarkCircuit,
    identity: Identity,
    idCommitments: SnarkBigInt[],
    treeDepth: number,
    recipientAddress: string,
    forwarderAddress: string,
    feeAmt: Number | number | SnarkBigInt,
    externalNullifier: SnarkBigInt,
)
```

- `circuit` is the output of `genCircuit()`.
- `identity` is the `Identity` whose identity commitment you want to prove is
  in the set of registered identities.
- `idCommitments` is an array of registered identity commmitments; i.e. the
  leaves of the tree.
- `treeDepth` is the number of levels which the Merkle tree used has
- `recipientAddress` is the address which should receive the funds
- `forwarderAddress:` is the address of the contract which will forward the transaction. This could be a [Surrogeth](https://github.com/lsankar4033/surrogeth) RelayerForwarder.
- `feeAmt` is the amount of ETH (in wei) or tokens deposited
- `externalNullifier` is the current external nullifier

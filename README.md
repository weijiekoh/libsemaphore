# A Semaphore and MicroMix client library

This repository contains the code necessary for third-party developers to
easily integrate Semaphore, a zero-knowledge signalling gadget, or MicroMix, a
mixer built upon Semaphore.

## Using libsemaphore to build a mixer

We refer below to any third-party app, like a mixer user interface, as a
*client*.

To use the mixer, each client must be able to:

1. Given a desired denomination and amount to mix (e.g. 10 DAI or 1 ETH),
   determine the correct Mixer contract.

2. Generate and store an `Identity` (which contains an `EddsaKeyPair`, identity
   nullifier, and identity trapdoor).

    - Use `genIdentity()`

3. Generate and store an identity commitment using the items above data.

    - Use `genIdentityCommitment(identity)` where `identity` is the return
      value of the above `genIdentity()`

4. Perform an Ethereum transaction containing the identity commitment as data
   to the desired Mixer contract's `deposit` or `depositERC20` function.

5. Download or load from disk a proving key and circuit file.

6. Retrieve a list of leaves from the Mixer contract using its `getLeaves()`
   view function.

7. Decide on a relayer to which to send a withdrawal transaction.


8. Generate a *witness* `w` using the list of leaves, the EdDSA keypair,
     identity nullifier, identity trapdoor, recipient's address, and a fee for the
     relayer. This step will fail if these inputs are invalid.

     - Use `genMixerWitness(...)` (see below for the parameters)

9. Generate a *proof* using `w` and the proving key.

    - Use `genProof(w, provingKey)`

9. Optionally download a verification key and use it to verify the proof before
   sending it to the Mixer contract.

   - To load the verifying key, which is a JSON file, note that all numeric
     values in it are represented by strings. A convenience function to
     un-stringify and parse the JSON is libsemaphore's
     `parseVerifyingKeyJson(verifyingKeyAsText)`.

   - To verify the proof off-chain, use the `verifyProof()` function.

10. Send the proof, recipient's address, fee, and relayers address, along with
    to the Mixer contract's `mix` or `mixERC20` function.

## Using libsemaphore to build other applications

Other applications of Semaphore, like private DAOs or anonymous login, use the
Semaphore contract differently than MicroMix. The steps to generate an identity
and identity commitment, however, remain the same. The identity commitment
should be sent to Semaphore's `insertIdentity()` contract function.

You can generate a witness with any arbitary signal using the `genWitness(...)`
function. See below for the required parameters.

## Available types, interfaces, and functions

### Types

**`EddsaPrivateKey`**

An [EdDSA](https://tools.ietf.org/html/rfc8032) private key which should be 32
bytes long.

Encapsulates a [`Buffer`](https://nodejs.org/api/buffer.html).

**`EddsaPublicKey`**

An EdDSA public key. Encapsulates an array of `snarkjs.bigInt`s.

**`SnarkProvingKey`**

A proving key, which when used with a secret *witness*, generates a zk-SNARK
proof about said witness. Encapsulates a `Buffer`.

**`SnarkVerifyingKey`**

A verifying key which when used with public inputs to a zk-SNARK and a
`SnarkProof`, can prove the proof's validity. Encapsulates a `Buffer`.

**`SnarkWitness`**

The secret inputs to a zk-SNARK. Encapsulates an array of `snarkjs.bigInt`s.

**`SnarkPublicSignals`**

The public inputs to a zk-SNARK. Encapsulates an array of `snarkjs.bigInt`s.

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
    identityNullifier: snarkjs.bigInt,
    identityTrapdoor: snarkjs.bigInt,
}
```

**`SnarkProof`**

Encapsulates zk-SNARK proof data required by `verifyProof()`.

```ts
interface SnarkProof {
    pi_a: snarkjs.bigInt[]
    pi_b: snarkjs.bigInt[][]
    pi_c: snarkjs.bigInt[]
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

**`genIdentityCommitment(identity: Identity): snarkjs.bigInt`**

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

**`signMsg(privKey: EddsaPrivateKey, msg: snarkjs.bigInt): EdDSAMiMcSpongeSignature)`**

Encapsualtes `circomlib.eddsa.signMiMCSponge` to sign a message `msg` using private key `privKey`.

**`verifySignature(msg: snarkjs.bigInt, signature: EdDSAMiMcSpongeSignature, pubKey: EddsaPublicKey)`: boolean**

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

Encapsulates `new snarkjs.Circuit(circuitDefinition)`. The `circuitDefinition`
object should be the `JSON.parse`d result of the `circom` command which
converts a `.circom` file to a `.json` file.

**`async genWitness(...): SnarkWitness`**

This function has the following signature:

```ts
const genWitness = async (
    signal: string,
    circuit: SnarkCircuit,
    identity: Identity,
    tree: tree.MerkleTree,
    nextIndex: number,
    identityCommitment: snarkjs.bigInt,
    externalNullifier: string,
)
```

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

### Mixer-specific functions 

**`genMixerSignal(recipientAddress: string, broadcasterAddress: string, feeAmt: Number | snarkjs.utils.BigNumber): string`**

Generates the signal that MicroMix needs. Returns a hex string.

It returns the Keccak256 hash of the recipient's address, broadcaster's
address, and the fee, in order to prevent frontrunning of `mix()` transactions.

Pass the signal to `genWitness`

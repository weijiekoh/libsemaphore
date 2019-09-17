# A Semaphore and MicroMix client library

This repository contains the code necessary for third-party developers to
easily integrate Semaphore, a zero-knowledge signalling gadget, or MicroMix, a
mixer built upon Semaphore.

## System design

We refer below to any third-party app, like a wallet user interface, as a
*client*.

To use the mixer, each client must be able to:

1. Given a desired denomination and amount to mix (e.g. 10 DAI or 1 ETH),
   determine the correct Mixer contract.

2. Generate and store an `Identity` (which contains an `EddsaKeyPair`, identity
   nullifier, and identity trapdoor).

3. Generate and store an identity commitment using the items above data.

4. Perform an Ethereum transaction containing the identity commitment as data
   to the desired Mixer contract's `deposit` or `depositERC20` function.

5. Download or load from disk a proving key and circuit file.

6. Retrieve a list of leaves from the Mixer contract using its `getLeaves()`
   view function.

7. Decide on a relayer to which to send a withdrawal transaction.

8. Generate a zk-SNARK proof using the proving key. This has two substeps:

    8.1. Generate a *witness* `w` using the list of leaves, the EdDSA keypair,
         identity nullifier, identity trapdoor, recipient's address, and a fee for the
         relayer. This step will fail if these inputs are invalid.

    8.2. Generate a *proof* using `w` and the proving key.

9. Optionally download a verification key and use it to verify the proof before
   sending it to the Mixer contract.

10. Send the proof, recipient's address, fee, and relayers address, along with
    to the Mixer contract's `mix` or `mixERC20` function.

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

**`async genMixerWitness(...): SnarkWitness`**

This function has the following signature:

```ts
const genMixerWitness = async (
    circuit: SnarkCircuit,
    identity: Identity,
    tree: tree.MerkleTree,
    nextIndex: number,
    identityCommitment: snarkjs.bigInt,
    recipientAddress: string,
    relayerAddress: string,
    feeAmt: Number | number | snarkjs.bigInt,
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

**`genProof(witness: SnarkWitness, provingKey: SnarkProvingKey): SnarkProof`**

Generates a `SnarkProof`, which can be sent to the Semaphore contract's
`broadcastSignal()` function, or the Mixer's `mix()` or `mixERC20` functions.
It can also be verified off-chain using `verifyProof()` below.

**`genPublicSignals(witness: SnarkWitness, circuit: SnarkCircuit): SnarkPublicSignals`**

Extracts the public signals to be supplied to the contract or `verifyProof()`.

**`verifyProof(verifyingKey: SnarkVerifyingKey, proof: SnarkProof, publicSignals: SnarkPublicSignals): boolean`**

Returns true if the given `proof` is valid, given the correct verifying key and
public signals.

Returns false otherwise.

### Mixer enumeration

Each Mixer contract handles a constant amount of ETH or ERC20 tokens. e.g.:

```
Contract 0xaaaaaaaaa...: 1 ETH deposits only
Contract 0xbbbbbbbbb...: 10 DAI deposits only
```

Anyone can deploy a mixer contract, but it does not make privacy or economic
sense to deploy multiple contracts of the same denomination, as that would
unnecessarily make each anonymity pool smaller. The only reason to deploy a
mixer contract if one already exists for said denomination is if a security
flaw was discovered in the original.

As such, wallet providers can simply preload the Mixer address they need
from a predefined list. We assume that users already trust the wallet provider
to provide the correct address, or else their ETH or tokens could be
transferred to a malicious actor's account instead.

### Transaction burn relay

###

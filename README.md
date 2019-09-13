# A modularised Ethereum mixer

MicroMix is an Ethereum mixer based on Semaphore. To attain a large enough
anonymity set and enhance privacy for all, it is necessary to attract and
retain as many users as possible in order to maximise all anonymity sets. One
way to do this is to integrate with popular wallet providers so that users can
mix their funds directly through their wallet user interface instead of using a
dApp like https://micromix.app.  To this end, this repository contains the code
necessary for an `npm` module which allows third-party wallet providers to
easily integrate MicroMix.

## System design

We refer below to any third-party wallet or user interface as a *client*.

To use the mixer, each client must be able to:

1. Given a desired denomination and amount to mix (e.g. 10 DAI or 1 ETH),
   determine the correct Mixer contract.

2. Generate and store an EdDSA keypair, identity nullifier, and identity trapdoor.

3. Generate and store an identity commitment using the items above data.

4. Perform an Ethereum transaction containing the identity commitment as data
   to the desired Mixer contract's `deposit` or `depositERC20` function.

5. Download or load from disk a proving key and circuit file.

6. Retrieve a list of leaves from the Mixer contract.

7. Decide on a relayer to which to send a withdrawal transaction.

8. Generate a zk-SNARK proof using the list of leaves, the EdDSA keypair,
   identity nullifier, identity trapdoor, recipient's address, and a fee for
   the relayer.

9. Optionally download a verification key and use it to verify the proof before
   sending it to the Mixer contract.

10. Send the proof, recipient's address, fee, and relayers address, along with
    to the Mixer contract's `mix` or `mixERC20` function.

## Library interface

### Types and interfaces

```ts
type EddsaPrivateKey = Buffer
type EddsaPublicKey = BigInt[]
type SnarkProvingKey = Buffer
type SnarkVerifyingKey = Buffer
```

### `EddsaKeyPair` interface

```ts
interface EddsaKeyPair {
    pubKey: EddsaPublicKey,
    privKey: EddsaPrivateKey,
 }
```

### `Identity` interface

```ts
interface Identity {
    keypair: EddsaKeyPair,
    identityNullifier: BigInt,
    identityTrapdoor: BigInt,
}
```

### `genPubKey(privKey: EddsaPrivateKey): EddsaPublicKey` function

Generates a public EdDSA key from a supplied private key.

### `genIdentity(): Identity` function

The 32-byte private key for the `EddsaKeyPair` is randomly generated, as are
the distinct 31-byte identity nullifier and the 31-byte identity trapdoor
values.

### `genIdentityCommitment(identity: Identity): BigInt` function

Generates an identity commitment, which is the hash of the public key, the
identity nullifier, and the identity trapdoor.

### `genProof(...)`
TODO


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

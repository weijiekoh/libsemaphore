import * as snarkjs from 'snarkjs'
import * as circomlib from 'circomlib'
import * as crypto from 'crypto'
import * as ethers from 'ethers'
import { convertWitness, prove, beBuff2int } from './utils' 
import { storage, hashers, tree } from 'semaphore-merkle-tree'
const eddsa = circomlib.eddsa
const MemStorage = storage.MemStorage
const MerkleTree = tree.MerkleTree
const MimcSpongeHasher = hashers.MimcSpongeHasher

export type EddsaPrivateKey = Buffer
export type EddsaPublicKey = snarkjs.bigInt[]
export type SnarkCircuit = snarkjs.Circuit
export type SnarkProvingKey = Buffer
export type SnarkVerifyingKey = Buffer
export type SnarkWitness = Array<snarkjs.bigInt>
export type SnarkPublicSignals = snarkjs.bigInt[]

interface EddsaKeyPair {
    pubKey: EddsaPublicKey,
    privKey: EddsaPrivateKey,
}

interface Identity {
    keypair: EddsaKeyPair,
    identityNullifier: snarkjs.bigInt,
    identityTrapdoor: snarkjs.bigInt,
}

interface SnarkProof {
    pi_a: snarkjs.bigInt[]
    pi_b: snarkjs.bigInt[][]
    pi_c: snarkjs.bigInt[]
}

interface EdDSAMiMcSpongeSignature {
    R8: snarkjs.bigInt[],
    S: snarkjs.bigInt,
}

const pedersenHash = (
    ints: snarkjs.bigInt[],
): snarkjs.bigInt => {

    const p = circomlib.babyJub.unpackPoint(
        circomlib.pedersenHash.hash(
            Buffer.concat(
                ints.map(x => x.leInt2Buff(32))
            )
        )
    )

    return snarkjs.bigInt(p[0])
}

const genRandomBuffer = (numBytes: number = 32): Buffer => {
    return crypto.randomBytes(numBytes)
}

const genPubKey = (privKey: EddsaPrivateKey): EddsaPublicKey => {
    const pubKey = eddsa.prv2pub(privKey)

    return pubKey
}

const genEddsaKeyPair = (
    privKey: Buffer = genRandomBuffer(),
): EddsaKeyPair => {

    const pubKey = genPubKey(privKey)
    return { pubKey, privKey }
}

const genIdentity = (
    privKey: Buffer = genRandomBuffer(32),
): Identity => {

    // The identity nullifier and identity trapdoor are separate random 31-byte
    // values
    return {
        keypair: genEddsaKeyPair(privKey),
        identityNullifier: snarkjs.bigInt.leBuff2int(genRandomBuffer(31)),
        identityTrapdoor: snarkjs.bigInt.leBuff2int(genRandomBuffer(31)),
    }
}

const genIdentityCommitment = (
    identity: Identity,
): snarkjs.bigInt => {

    return pedersenHash([
        circomlib.babyJub.mulPointEscalar(identity.keypair.pubKey, 8)[0],
        identity.identityNullifier,
        identity.identityTrapdoor,
    ])
}

const genMixerMsg = (
    externalNullifier: string,
    signalHash: snarkjs.bigInt,
): snarkjs.bigInt => {

    return circomlib.mimcsponge.multiHash([
        snarkjs.bigInt(externalNullifier),
        snarkjs.bigInt(signalHash), 
    ])
}

const signMsg = (
    privKey: EddsaPrivateKey,
    msg: snarkjs.bigInt,
): EdDSAMiMcSpongeSignature => {

    return eddsa.signMiMCSponge(privKey, msg)
}

const genSignedMsg = (
    privKey: EddsaPrivateKey,
    externalNullifier: string,
    signalHash: snarkjs.bigInt,
) => {
    const msg = genMixerMsg(externalNullifier, signalHash)

    return {
        msg,
        signature: signMsg(privKey, msg),
    }
}

const genPathElementsAndIndex = async (tree, identityCommitment) => {
    const leafIndex = await tree.element_index(identityCommitment)
    const identityPath = await tree.path(leafIndex)
    const identityPathElements = identityPath.path_elements
    const identityPathIndex = identityPath.path_index

    return { identityPathElements, identityPathIndex }
}

const verifySignature = (
    msg: snarkjs.bigInt,
    signature: EdDSAMiMcSpongeSignature,
    pubKey: EddsaPublicKey,
): boolean => {

    return eddsa.verifyMiMCSponge(msg, signature, pubKey)
}

const genMixerSignal = (
    recipientAddress: string,
    broadcasterAddress: string,
    feeAmt: Number | snarkjs.utils.BigNumber,
) => {
    return ethers.utils.solidityKeccak256(
        ['address', 'address', 'uint256'],
        [recipientAddress, broadcasterAddress, feeAmt.toString()],
    )
}

const keccak256HexToBigInt = (
    signal: string,
): snarkjs.bigInt => {
    const signalAsBuffer = Buffer.from(signal.slice(2), 'hex')
    const signalHashRaw = ethers.utils.solidityKeccak256(
        ['bytes'],
        [signalAsBuffer],
    )
    const signalHashRawAsBytes = Buffer.from(signalHashRaw.slice(2), 'hex');
    const signalHash: snarkjs.bigInt = beBuff2int(signalHashRawAsBytes.slice(0, 31))

    return signalHash
}

const genCircuit = (circuitDefinition: any) => {
    return new snarkjs.Circuit(circuitDefinition)
}

const genWitness = async (
    signal: string,
    circuit: SnarkCircuit,
    identity: Identity,
    tree: tree.MerkleTree,
    nextIndex: number,
    identityCommitment: snarkjs.bigInt,
    externalNullifier: string,
) => {
    await tree.update(nextIndex, identityCommitment.toString())

    const identityPath = await tree.path(nextIndex)

    const { identityPathElements, identityPathIndex } = await genPathElementsAndIndex(
        tree,
        identityCommitment,
    )

    const signalHash = keccak256HexToBigInt(signal)

    const { signature, msg } = genSignedMsg(
        identity.keypair.privKey,
        externalNullifier,
        signalHash, 
    )
   
    const witness = circuit.calculateWitness({
        'identity_pk[0]': identity.keypair.pubKey[0],
        'identity_pk[1]': identity.keypair.pubKey[1],
        'auth_sig_r[0]': signature.R8[0],
        'auth_sig_r[1]': signature.R8[1],
        auth_sig_s: signature.S,
        signal_hash: signalHash,
        external_nullifier: snarkjs.bigInt(externalNullifier),
        identity_nullifier: identity.identityNullifier,
        identity_trapdoor: identity.identityTrapdoor,
        identity_path_elements: identityPathElements,
        identity_path_index: identityPathIndex,
        fake_zero: snarkjs.bigInt(0),
    })

    return {
        witness,
        signal,
        signalHash,
        signature,
        msg,
        tree,
        identityPath,
        identityPathIndex,
        identityPathElements,
    }
}

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
) => {

    await tree.update(nextIndex, identityCommitment.toString())

    const identityPath = await tree.path(nextIndex)

    const { identityPathElements, identityPathIndex } = await genPathElementsAndIndex(
        tree,
        identityCommitment,
    )

    const signal = genMixerSignal(
        recipientAddress, relayerAddress, feeAmt,
    )

    const signalHash = keccak256HexToBigInt(signal)

    const { signature, msg } = genSignedMsg(
        identity.keypair.privKey,
        externalNullifier,
        signalHash, 
    )
   
    const witness = circuit.calculateWitness({
        'identity_pk[0]': identity.keypair.pubKey[0],
        'identity_pk[1]': identity.keypair.pubKey[1],
        'auth_sig_r[0]': signature.R8[0],
        'auth_sig_r[1]': signature.R8[1],
        auth_sig_s: signature.S,
        signal_hash: signalHash,
        external_nullifier: snarkjs.bigInt(externalNullifier),
        identity_nullifier: identity.identityNullifier,
        identity_trapdoor: identity.identityTrapdoor,
        identity_path_elements: identityPathElements,
        identity_path_index: identityPathIndex,
    })

    return {
        witness,
        signal,
        signalHash,
        signature,
        msg,
        tree,
        identityPath,
        identityPathIndex,
        identityPathElements,
    }
}

const setupTree = (
    levels: number,
    prefix: string = 'semaphore',
): tree.MerkleTree => {
    const storage = new MemStorage()
    const hasher = new MimcSpongeHasher()

    return new MerkleTree(
        prefix,
        storage,
        hasher,
        levels,
        0,
    )
}

const genProof = async (
    witness: any,
    provingKey: SnarkProvingKey,
): Promise<SnarkProof> => {

    const witnessBin = convertWitness(snarkjs.stringifyBigInts(witness))

    return await prove(witnessBin.buffer, provingKey.buffer)
}

const genPublicSignals = (
    witness: any,
    circuit: snarkjs.Circuit,
) => {

    return witness.slice(1, circuit.nPubInputs + circuit.nOutputs+1)
}

const parseVerifyingKeyJson = (
    verifyingKeyStr: string,
) => {
    return snarkjs.unstringifyBigInts(JSON.parse(verifyingKeyStr))
}

const verifyProof = (
    verifyingKey: SnarkVerifyingKey,
    proof: SnarkProof,
    publicSignals: SnarkPublicSignals
): boolean => {

    return snarkjs.groth.isValid(verifyingKey, proof, publicSignals)
}

// "export = {" ????
export {
    parseVerifyingKeyJson,
    setupTree,
    genPubKey,
    genIdentity,
    genWitness,
    genMixerWitness,
    genProof,
    genPublicSignals,
    genCircuit,
    verifyProof,
    verifySignature,
    signMsg,
    genIdentityCommitment,
}

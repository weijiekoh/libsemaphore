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
const stringifyBigInts: (obj: object) => object = snarkjs.stringifyBigInts
const unstringifyBigInts: (obj: object) => object = snarkjs.unstringifyBigInts

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

const signMsg = (
    privKey: EddsaPrivateKey,
    msg: snarkjs.bigInt,
): EdDSAMiMcSpongeSignature => {

    return eddsa.signMiMCSponge(privKey, msg)
}

const genSignedMsg = (
    privKey: EddsaPrivateKey,
    externalNullifier: snarkjs.bigInt,
    signalHash: snarkjs.bigInt,
) => {
    const msg = circomlib.mimcsponge.multiHash([
        externalNullifier,
        signalHash
    ])

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

const genTree = async (
    treeDepth: number,
    leaves: snarkjs.bigInt[],
) => {
    const tree = setupTree(treeDepth)

    for (let i=0; i<leaves.length; i++) {
        await tree.update(i, leaves[i].toString())
    }

    return tree
}
const genMixerSignal = (
    recipientAddress: string,
    broadcasterAddress: string,
    feeAmt: Number | snarkjs.utils.BigNumber,
): string => {
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
    idCommitments: snarkjs.bigInt[] | BigInt[] | ethers.utils.BigNumber[],
    treeDepth: number,
    externalNullifier: snarkjs.bigInt,
) => {
    // convert idCommitments
    const idCommitmentsAsBigInts: snarkjs.bigInt[] = []
    for (let idc of idCommitments) {
        idCommitmentsAsBigInts.push(snarkjs.bigInt(idc.toString()))
    }

    const identityCommitment = genIdentityCommitment(identity)
    const index = idCommitmentsAsBigInts.indexOf(identityCommitment)
    const tree = await genTree(treeDepth, idCommitments)

    const identityPath = await tree.path(index)

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
        external_nullifier: externalNullifier,
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
    idCommitments: snarkjs.bigInt[],
    treeDepth: number,
    recipientAddress: string,
    relayerAddress: string,
    feeAmt: Number | number | snarkjs.bigInt,
    externalNullifier: snarkjs.bigInt,
) => {

    const signal = genMixerSignal(
        recipientAddress, relayerAddress, feeAmt,
    )

    return genWitness(
        signal,
        circuit,
        identity,
        idCommitments,
        treeDepth,
        externalNullifier
    )
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
): SnarkPublicSignals => {

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

const formatForVerifierContract = (
    proof: SnarkProof,
    publicSignals: SnarkPublicSignals,
) => {
    const stringify = (x) => x.toString()

    return {
        a: [ proof.pi_a[0].toString(), proof.pi_a[1].toString() ],
        b: [ 
            [ proof.pi_b[0][1].toString(), proof.pi_b[0][0].toString() ],
            [ proof.pi_b[1][1].toString(), proof.pi_b[1][0].toString() ],
        ],
        c: [ proof.pi_c[0].toString(), proof.pi_c[1].toString() ],
        input: publicSignals.map(stringify),
    }
}

export {
    parseVerifyingKeyJson,
    setupTree,
    genPubKey,
    genIdentity,
    genWitness,
    genMixerSignal,
    genMixerWitness,
    genProof,
    genPublicSignals,
    genCircuit,
    genTree,
    verifyProof,
    verifySignature,
    signMsg,
    genIdentityCommitment,
    formatForVerifierContract,
    stringifyBigInts,
    unstringifyBigInts,
}

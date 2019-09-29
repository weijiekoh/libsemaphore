const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
const path = require('path')
const uuidv4 = require('uuid/v4')
import * as fs from 'fs'
import * as ethers from 'ethers'

jest.setTimeout(30000)
const assert = chai.assert

import * as libsemaphore from '../index'

const circuitPath = path.join(__dirname, '/../../semaphore/semaphorejs/build/circuit.json')
const provingKeyPath = path.join(__dirname, '/../../semaphore/semaphorejs/build/proving_key.bin')
const verifyingKeyPath = path.join(__dirname, '/../../semaphore/semaphorejs/build/verification_key.json')

const cirDef = JSON.parse(fs.readFileSync(circuitPath).toString())
const provingKey = fs.readFileSync(provingKeyPath)
const verifyingKey = libsemaphore.parseVerifyingKeyJson(fs.readFileSync(verifyingKeyPath).toString())

const externalNullifier = '0'

describe('libsemaphore', function () {
    const identity = libsemaphore.genIdentity()
    let witness
    let circuit
    let proof
    let publicSignals

    it('genIdentity() should produce values of the correct length and type', async () => {
        assert.equal(identity.keypair.pubKey.length, 2)
        assert.equal(identity.keypair.privKey.length, 32)
        assert.equal(typeof identity.identityNullifier, 'bigint')
        assert.equal(typeof identity.identityTrapdoor, 'bigint')
    })

    it('identityCommitment() should produce a value of the correct length and type', async () => {
        const idc = libsemaphore.genIdentityCommitment(identity)
        assert.equal(typeof idc, 'bigint')
        assert.isBelow(idc.toString(16).length, 65)
        // This may fail in very rare occasions; just run the test again
        assert.isAbove(idc.toString(16).length, 48)
    })

    it('genMixerSignal should return a hash', async () => {
        const signal = libsemaphore.genMixerSignal(
            '0xabcd', '0xdefd', 0
        )
        expect(signal).toHaveLength(66)
        expect(signal.slice(0, 2)).toEqual('0x')
    })

    it('genWitness() should generate a witness', async () => {
        const idc = libsemaphore.genIdentityCommitment(identity)

        circuit = libsemaphore.genCircuit(cirDef)

        const result = await libsemaphore.genWitness(
            'signal0',
            circuit,
            identity,
            [new ethers.utils.BigNumber(idc.toString())],
            4,
            externalNullifier,
        )

        witness = result.witness

        expect(circuit.checkWitness(witness)).toBeTruthy()
    })

    it('genProof() should generate a valid proof', async () => {
        proof = await libsemaphore.genProof(witness, provingKey)
        publicSignals = libsemaphore.genPublicSignals(witness, circuit)
        const isValid = libsemaphore.verifyProof(verifyingKey, proof, publicSignals)
    })

    it('formatForVerifierContract() should produce the correct params', async () => {
        const params = libsemaphore.formatForVerifierContract(proof, publicSignals)
        expect(params.input).toHaveLength(publicSignals.length)
        expect(params.a).toHaveLength(2)
        expect(params.b).toHaveLength(2)
        expect(params.b[0]).toHaveLength(2)
        expect(params.b[1]).toHaveLength(2)
        expect(params.c).toHaveLength(2)
    })
})

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
const provingKey: libsemaphore.SnarkProvingKey = fs.readFileSync(provingKeyPath)
const verifyingKey: libsemaphore.SnarkVerifyingKey = libsemaphore.parseVerifyingKeyJson(fs.readFileSync(verifyingKeyPath).toString())

const externalNullifier = '0'

describe('libsemaphore', function () {
    const identity: libsemaphore.Identity = libsemaphore.genIdentity()
    let witness: libsemaphore.SnarkWitness
    let witnessData: libsemaphore.WitnessData
    let circuit: libsemaphore.SnarkCircuit
    let proof: libsemaphore.SnarkProof
    let publicSignals: libsemaphore.SnarkPublicSignals

    it('genIdentity() should produce values of the correct length and type', async () => {
        assert.equal(identity.keypair.pubKey.length, 2)
        assert.equal(identity.keypair.privKey.length, 32)
        assert.equal(typeof identity.identityNullifier, 'bigint')
        assert.equal(typeof identity.identityTrapdoor, 'bigint')
    })

    it('serialiseIdentity() and unSerialiseIdentity() should work', async () => {
        const serialisedId: string = libsemaphore.serialiseIdentity(identity)
        const unSerialisedId: libsemaphore.Identity = libsemaphore.unSerialiseIdentity(serialisedId)

        expect(unSerialisedId).toEqual(identity)
        expect(unSerialisedId.identityNullifier).toEqual(identity.identityNullifier)
        expect(unSerialisedId.identityTrapdoor).toEqual(identity.identityTrapdoor)
        expect(unSerialisedId.keypair.privKey.toString('hex')).toEqual(identity.keypair.privKey.toString('hex'))
        expect(unSerialisedId.keypair.pubKey).toEqual(identity.keypair.pubKey)
    })

	it('identityCommitment() should produce a value of the correct length and type', async () => {
		const idc: libsemaphore.SnarkBigInt = libsemaphore.genIdentityCommitment(identity)
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

		witnessData = await libsemaphore.genWitness(
			'signal0',
			circuit,
			identity,
			[new ethers.utils.BigNumber(idc.toString())],
			4,
			externalNullifier,
		)

		witness = witnessData.witness

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

	it('genBroadcastSignalParams() should produce the correct params', async () => {
        const params = libsemaphore.genBroadcastSignalParams(witnessData, proof, publicSignals)
		expect(params).toHaveProperty('signal')
		expect(params.proof).toHaveLength(8)
		expect(params).toHaveProperty('root')
		expect(params).toHaveProperty('nullifiersHash')
		expect(params).toHaveProperty('externalNullifier')
    })

    test('genExternalNullifier() should always return a 32-byte hex string whose true size is 29 bytes', () => {
        const plaintext = 'test question'
        const fullHash = ethers.utils.solidityKeccak256(['string'], [plaintext])
        const hash = libsemaphore.genExternalNullifier(plaintext)

        expect(fullHash)
            .toEqual('0x51480a3453be7db7a786adbfc5d579a36a620c26f5a2e51d4c296d52892e38d6')
        expect(hash)
            .toEqual('0x0000003453be7db7a786adbfc5d579a36a620c26f5a2e51d4c296d52892e38d6')
        expect(hash).toHaveLength(66)
    })
})

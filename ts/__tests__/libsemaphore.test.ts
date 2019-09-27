const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
const path = require('path')
const uuidv4 = require('uuid/v4')
import * as fs from 'fs'

const assert = chai.assert

import * as libsemaphore from '../index'

const circuitPath = path.join(__dirname, '/../../semaphore/semaphorejs/build/circuit.json')
const provingKeyPath = path.join(__dirname, '/../../semaphore/semaphorejs/build/provingKey.bin')

const externalNullifier = '0'

describe('libsemaphore', function () {
    const identity = libsemaphore.genIdentity()

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

    it('genWitness() should generate a witness', async () => {
        const tree = libsemaphore.setupTree(4)
        const idc = libsemaphore.genIdentityCommitment(identity)

        const cirDef = JSON.parse(
            fs.readFileSync(circuitPath).toString()
        )

        const circuit = libsemaphore.genCircuit(cirDef)

        const { witness } = await libsemaphore.genWitness(
            'signal0',
            circuit,
            identity,
            tree,
            0,
            idc,
            externalNullifier,
        )
        expect(circuit.checkWitness(witness)).toBeTruthy()
    })

    //it('genProof() should generate a valid proof', async () => {
    //})
})

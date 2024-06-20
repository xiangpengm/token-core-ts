import { expect } from 'chai'
import { Bytes } from 'scryptlib'
import { bsv as mvc } from 'scrypt-ts'
import {
    getPreimage,
    signTx,
    Ripemd160,
    Sig,
    toHex,
    PubKey,
    SigHashPreimage,
} from 'scryptlib'
import * as Common from '../src/contracts/utils/Common'
import { myPrivateKey as privateKey } from './utils/privateKey'
import { inputSatoshis, dummyTxId } from './utils/scryptHelper'
// contracts
import { ProtoHeader } from '../src/contracts/protoheader'
import { TokenProto } from '../src/contracts/token/tokenProto'

const genContract = Common.genContract
const addInput = Common.addInput
const addOutput = Common.addOutput

const Genesis = genContract('token/tokenGenesis')
const Token = genContract('token/token')

const issuerPrivKey = privateKey
const issuerPubKey = privateKey.publicKey
const issuerAddress = privateKey.toAddress()
const tokenVersion = Common.getUInt32Buf(1)
const tokenType = Common.getUInt32Buf(1)
const PROTO_FLAG = Buffer.from(ProtoHeader.PROTO_FLAG, 'hex')
const address1 = privateKey.toAddress()
const tokenValue = 1000000
const buffValue = Buffer.alloc(8, 0)
buffValue.writeBigUInt64LE(BigInt(tokenValue))
const transferCheckCodeHash = Bytes(Buffer.alloc(20, 0).toString('hex'))
const transferCheckCodeHashArray = [
    transferCheckCodeHash,
    transferCheckCodeHash,
    transferCheckCodeHash,
    transferCheckCodeHash,
    transferCheckCodeHash,
]
const unlockContractCodeHashArray = transferCheckCodeHashArray

const sigtype = Common.SIG_HASH_ALL

const TOKEN_NAME = Buffer.alloc(Number(TokenProto.TOKEN_NAME_LEN), 0)
TOKEN_NAME.write('test token name')
const TOKEN_SYMBOL = Buffer.alloc(Number(TokenProto.TOKEN_SYMBOL_LEN), 0)
TOKEN_SYMBOL.write('test')
const DECIMAL_NUM = Buffer.from('08', 'hex')

let genesisTxidBuf, genesisHash, genesisTx, prevGenesisTx

function createGenesis(sID: Buffer) {
    const genesis = new Genesis()
    const contractData = Buffer.concat([
        TOKEN_NAME,
        TOKEN_SYMBOL,
        DECIMAL_NUM,
        issuerAddress.hashBuffer, // address
        Buffer.alloc(8, 0), // token value
        Buffer.alloc(20, 0), // genesisHash
        sID, // genesisTxidBuf
        tokenVersion,
        tokenType, // type
        PROTO_FLAG,
    ])
    genesis.setDataPartInASM(
        Common.buildScriptData(contractData).toString('hex')
    )
    return genesis
}

async function unlockGenesis(
    tx: mvc.Transaction,
    genesis,
    tokenScript,
    genesisTx: mvc.Transaction,
    prevInputIndex: number,
    prevGenesisTx: mvc.Transaction,
    prevOutputIndex: number,
    changeAddress: mvc.Address,
    changeSatoshis: number,
    expected = true
) {
    const inputIndex = 0
    const preimage = getPreimage(
        tx,
        genesis.lockingScript,
        inputSatoshis,
        inputIndex,
        sigtype
    )
    const sig = signTx(
        tx,
        issuerPrivKey,
        genesis.lockingScript,
        inputSatoshis,
        inputIndex
    )

    // get input proof
    const { inputProofInfo, txHeader } = Common.getTxInputProof(
        genesisTx,
        prevInputIndex
    )

    // get prev output proof
    const prevOutputProof = Common.getTxOutputProof(
        prevGenesisTx,
        prevOutputIndex
    )

    const txContext = {
        tx: tx,
        inputIndex: inputIndex,
        inputSatoshis: inputSatoshis,
    }

    const result = genesis
        .unlock(
            SigHashPreimage(toHex(preimage)),
            PubKey(toHex(issuerPubKey)),
            Sig(toHex(sig)),
            Bytes(tokenScript.toHex()),
            // genesisTx input proof
            txHeader,
            BigInt(prevInputIndex),
            inputProofInfo,
            // prev genesis tx output proof
            prevOutputProof.txHeader,
            prevOutputProof.hashProof,
            prevOutputProof.satoshiBytes,
            // output
            BigInt(inputSatoshis), // genesisSatoshis
            BigInt(inputSatoshis), // tokenSatoshis
            Ripemd160(changeAddress.hashBuffer.toString('hex')),
            BigInt(changeSatoshis),
            Bytes('') //opReturnScript
        )
        .verify(txContext)

    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function createToken(genesis, contractData: Buffer, options: any = {}) {
    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    if (options.wrongVersion) {
        tx.version = 1
    }

    const genesisScript = genesis.lockingScript
    const scriptBuf = genesisScript.toBuffer()
    const newScriptBuf = Buffer.from(
        TokenProto.getNewGenesisScript(
            scriptBuf.toString('hex'),
            BigInt(scriptBuf.length),
            genesisTxidBuf
        ),
        'hex'
    )

    const prevouts = []

    // input
    // genesis
    addInput(
        tx,
        genesisTx.id,
        0,
        genesis.lockingScript,
        inputSatoshis,
        prevouts
    )

    // mvc
    addInput(
        tx,
        dummyTxId,
        0,
        mvc.Script.buildPublicKeyHashOut(issuerAddress),
        inputSatoshis,
        prevouts
    )

    // output
    // genesis
    addOutput(tx, mvc.Script.fromBuffer(newScriptBuf), inputSatoshis)

    // token
    const token = new Token(
        transferCheckCodeHashArray,
        unlockContractCodeHashArray
    )
    token.setDataPartInASM(Common.buildScriptData(contractData).toString('hex'))
    const tokenScript = token.lockingScript
    addOutput(tx, tokenScript, inputSatoshis)

    const prevInputIndex = 0
    const prevOutputIndex = 0

    unlockGenesis(
        tx,
        genesis,
        tokenScript,
        genesisTx,
        prevInputIndex,
        prevGenesisTx,
        prevOutputIndex,
        address1,
        0,
        options.expected
    )

    return tx
}

describe('Test genesis contract unlock In Javascript', () => {
    before(() => {
        const genesis = createGenesis(Buffer.alloc(36, 0))
        const genesisScript = genesis.lockingScript
        const scriptBuf = genesisScript.toBuffer()

        // create prevGenesisTx
        prevGenesisTx = new mvc.Transaction()
        prevGenesisTx.version = Common.TX_VERSION
        const prevouts = []
        addInput(
            prevGenesisTx,
            dummyTxId,
            0,
            mvc.Script.buildPublicKeyHashOut(issuerAddress),
            inputSatoshis,
            prevouts
        )

        addOutput(
            prevGenesisTx,
            mvc.Script.buildPublicKeyHashOut(issuerAddress),
            inputSatoshis
        )

        // create genesisTx
        genesisTx = new mvc.Transaction()
        genesisTx.version = Common.TX_VERSION
        addInput(
            genesisTx,
            prevGenesisTx.id,
            0,
            prevGenesisTx.outputs[0].script,
            inputSatoshis,
            prevouts
        )
        addOutput(genesisTx, genesis.lockingScript, inputSatoshis)

        genesisTxidBuf = Buffer.from(
            Common.genGenesisTxid(genesisTx.id, 0),
            'hex'
        )

        const newScriptBuf = Buffer.from(
            TokenProto.getNewGenesisScript(
                scriptBuf.toString('hex'),
                BigInt(scriptBuf.length),
                genesisTxidBuf
            ),
            'hex'
        )
        genesisHash = Common.getScriptHashBuf(newScriptBuf)

        const contractData = Buffer.concat([
            TOKEN_NAME,
            TOKEN_SYMBOL,
            DECIMAL_NUM,
            address1.hashBuffer,
            buffValue,
            genesisHash,
            genesisTxidBuf,
            tokenVersion,
            tokenType, // type
            PROTO_FLAG,
        ])

        const tx = createToken(genesis, contractData)

        prevGenesisTx = genesisTx
        genesisTx = tx
    })

    it('g1: should succeed when issue token', () => {
        // add genesis output
        const contractData = Buffer.concat([
            TOKEN_NAME,
            TOKEN_SYMBOL,
            DECIMAL_NUM,
            address1.hashBuffer,
            buffValue,
            genesisHash,
            genesisTxidBuf,
            tokenVersion,
            tokenType, // type
            PROTO_FLAG,
        ])
        // issue again
        const genesis = createGenesis(genesisTxidBuf)
        const tx = createToken(genesis, contractData)

        prevGenesisTx = genesisTx
        genesisTx = tx
        // issue again to test Backtrace.verify
        createToken(genesis, contractData)
    })

    it('g2: should failed when add wrong data length', () => {
        const contractData = Buffer.concat([
            TOKEN_NAME,
            TOKEN_SYMBOL,
            DECIMAL_NUM,
            tokenVersion,
            tokenType, // type
            PROTO_FLAG,
            address1.hashBuffer,
            buffValue,
            genesisHash,
            genesisTxidBuf,
            Buffer.alloc(1, 0),
        ])
        const genesis = createGenesis(genesisTxidBuf)
        createToken(genesis, contractData, { expected: false })
    })

    it('g3: should failed when get wrong tokenID', () => {
        const contractData = Buffer.concat([
            TOKEN_NAME,
            TOKEN_SYMBOL,
            DECIMAL_NUM,
            tokenVersion,
            tokenType, // type
            PROTO_FLAG,
            address1.hashBuffer,
            buffValue,
            genesisHash,
            Buffer.alloc(genesisTxidBuf.length, 0), // script code hash
        ])
        const genesis = createGenesis(genesisTxidBuf)
        createToken(genesis, contractData, { expected: false })
    })

    it('g4: should failed when get wrong genesisHash', () => {
        const contractData = Buffer.concat([
            TOKEN_NAME,
            TOKEN_SYMBOL,
            DECIMAL_NUM,
            tokenVersion,
            tokenType, // type
            PROTO_FLAG,
            address1.hashBuffer,
            buffValue,
            Buffer.alloc(20, 0), // genesisHash
            genesisTxidBuf,
        ])
        const genesis = createGenesis(genesisTxidBuf)
        createToken(genesis, contractData, { expected: false })
    })

    it('g5: should failed when get wrong tx version', () => {
        const contractData = Buffer.concat([
            TOKEN_NAME,
            TOKEN_SYMBOL,
            DECIMAL_NUM,
            address1.hashBuffer,
            buffValue,
            genesisHash,
            genesisTxidBuf,
            tokenVersion,
            tokenType, // type
            PROTO_FLAG,
        ])
        const genesis = createGenesis(genesisTxidBuf)
        createToken(genesis, contractData, {
            wrongVersion: true,
            expected: false,
        })
    })
})

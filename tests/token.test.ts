import { expect } from 'chai'
import {
    bsv as mvc,
    getPreimage,
    toHex,
    SigHashPreimage,
    signTx,
    PubKey,
    Sig,
    Bytes,
    Ripemd160,
} from 'scryptlib'
import { inputSatoshis, dummyTxId } from './utils/scryptHelper'
import * as Utils from './tokenUtils'
// contracts
import { TokenProto } from '../src/contracts/token/tokenProto'

import { privateKey, privateKey2 } from './utils/privateKey'
import * as Common from '../src/contracts/utils/Common'

const addInput = Common.addInput
const addOutput = Common.addOutput
const genContract = Common.genContract

const sigtype = Common.SIG_HASH_ALL

const issuerAddress = privateKey.toAddress()
const address1 = privateKey.toAddress()
const address2 = privateKey2.toAddress()
const genesisTxid = Buffer.concat([
    Common.getTxIdBuf(dummyTxId),
    Common.getUInt32Buf(0),
])
let tokenID
const tokenID2 = Buffer.alloc(20, 0)

let transferCheckCodeHashArray
let unlockContractCodeHashArray
let genesisHash
let genesisScriptBuf
let tokenCodeHash

const maxInputLimit = 3
const maxOutputLimit = 3
const amountCheckHashIndex = 0

const Genesis = genContract('token/tokenGenesis')
const Token = genContract('token/token')
const TransferCheck = genContract('token/tokenTransferCheck')
const UnlockContractCheck = genContract('token/tokenUnlockContractCheck')
const TokenSell = genContract('token/tokenSell')

// const { TxInputProof, TxOutputProof } = buildTypeClasses(Token.artifact)

function initContractHash() {
    const transferCheckCode = new TransferCheck()
    let code = Buffer.concat([
        transferCheckCode.lockingScript.toBuffer(),
        Buffer.from('6a', 'hex'),
    ])
    const transferCheckCodeHash = Bytes(
        Common.getScriptHashBuf(code).toString('hex')
    )
    transferCheckCodeHashArray = [
        transferCheckCodeHash,
        transferCheckCodeHash,
        transferCheckCodeHash,
        transferCheckCodeHash,
        transferCheckCodeHash,
    ]

    const unlockContract = new UnlockContractCheck()
    code = Buffer.concat([
        unlockContract.lockingScript.toBuffer(),
        Buffer.from('6a', 'hex'),
    ])
    const unlockContractCodeHash = Bytes(
        Common.getScriptHashBuf(code).toString('hex')
    )
    unlockContractCodeHashArray = [
        unlockContractCodeHash,
        unlockContractCodeHash,
        unlockContractCodeHash,
        unlockContractCodeHash,
        unlockContractCodeHash,
    ]

    const genesis = Utils.createGenesisContract(
        Genesis,
        issuerAddress,
        genesisTxid
    )
    genesisScriptBuf = genesis.lockingScript.toBuffer()
    genesisHash = Common.getScriptHashBuf(genesisScriptBuf)
    const tokenIDData = Buffer.concat([genesisHash, genesisTxid])
    tokenID = mvc.crypto.Hash.sha256ripemd160(tokenIDData)
    //console.log("genesisHash:", genesisHash)

    const tokenContract = new Token(
        transferCheckCodeHashArray,
        unlockContractCodeHashArray
    )
    code = Buffer.concat([
        tokenContract.lockingScript.toBuffer(),
        Buffer.from('6a', 'hex'),
    ])
    tokenCodeHash = Common.getScriptHashBuf(code)
}

function createTokenContract(addressBuf: Buffer, amount: bigint) {
    return Utils.createTokenContract(
        Token,
        addressBuf,
        amount,
        genesisHash,
        genesisTxid,
        transferCheckCodeHashArray,
        unlockContractCodeHashArray
    )
}

function createTransferCheckContract(
    nTokenInputs,
    nOutputs,
    outputTokenArray,
    tid = tokenID,
    tcHash = tokenCodeHash
) {
    const { receiverArray, receiverTokenAmountArray } = genReceiverData(
        nOutputs,
        outputTokenArray
    )
    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    addInput(
        tx,
        dummyTxId,
        0,
        mvc.Script.buildPublicKeyHashOut(address1),
        inputSatoshis,
        []
    )

    const transferCheck = new TransferCheck()
    const data = Buffer.concat([
        Common.getUInt32Buf(nTokenInputs),
        receiverTokenAmountArray,
        receiverArray,
        Common.getUInt32Buf(nOutputs),
        tcHash,
        tid,
    ])
    const transferData = Common.buildScriptData(data)
    transferCheck.setDataPartInASM(transferData.toString('hex'))
    const transferCheckScript = transferCheck.lockingScript
    tx.addOutput(
        new mvc.Transaction.Output({
            script: transferCheckScript,
            satoshis: inputSatoshis,
        })
    )
    return {
        amountCheck: transferCheck,
        amountCheckTx: tx,
        amountCheckScriptData: Common.buildOpReturnData(transferData),
    }
}

function genReceiverData(nOutputs, outputTokenArray) {
    let receiverArray = Buffer.alloc(0)
    let receiverTokenAmountArray = Buffer.alloc(0)
    for (let i = 0; i < nOutputs; i++) {
        receiverArray = Buffer.concat([receiverArray, address2.hashBuffer])
        const tokenBuf = Buffer.alloc(8, 0)
        tokenBuf.writeBigUInt64LE(BigInt(outputTokenArray[i]))
        receiverTokenAmountArray = Buffer.concat([
            receiverTokenAmountArray,
            tokenBuf,
        ])
    }
    return { receiverArray, receiverTokenAmountArray }
}

function createUnlockContractCheck(
    tokenInputIndexArray,
    nTokenOutputs,
    tokenOutputAmounts,
    tokenOutputAddress,
    tid = tokenID,
    tcHash = tokenCodeHash
) {
    const unlockContractCheck = new UnlockContractCheck()

    const nTokenInputs = tokenInputIndexArray.length
    let tokenInputIndexBytes = Buffer.alloc(0)
    for (let i = 0; i < nTokenInputs; i++) {
        tokenInputIndexBytes = Buffer.concat([
            tokenInputIndexBytes,
            Common.getUInt32Buf(tokenInputIndexArray[i]),
        ])
    }

    let receiverTokenAmountArray = Buffer.alloc(0)
    let receiverArray = Buffer.alloc(0)
    for (let i = 0; i < nTokenOutputs; i++) {
        receiverArray = Buffer.concat([receiverArray, tokenOutputAddress[i]])
        receiverTokenAmountArray = Buffer.concat([
            receiverTokenAmountArray,
            Common.getUInt64Buf(tokenOutputAmounts[i]),
        ])
    }
    const data = Buffer.concat([
        tokenInputIndexBytes,
        Common.getUInt32Buf(nTokenInputs),
        receiverTokenAmountArray,
        receiverArray,
        Common.getUInt32Buf(nTokenOutputs),
        tcHash,
        Buffer.from(tid, 'hex'),
    ])
    const unlockContractCheckData = Common.buildScriptData(data)
    unlockContractCheck.setDataPartInASM(
        unlockContractCheckData.toString('hex')
    )
    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    addInput(
        tx,
        dummyTxId,
        0,
        mvc.Script.buildPublicKeyHashOut(address1),
        inputSatoshis,
        []
    )

    tx.addOutput(
        new mvc.Transaction.Output({
            script: unlockContractCheck.lockingScript,
            satoshis: inputSatoshis,
        })
    )

    return {
        amountCheck: unlockContractCheck,
        amountCheckTx: tx,
        amountCheckScriptData: Common.buildOpReturnData(
            unlockContractCheckData
        ),
    }
}

function unlockTransferCheck(
    tx: mvc.Transaction,
    prevouts: Buffer,
    transferCheck,
    inputIndex: number,
    tokenTxArray: mvc.Transaction[],
    tokenOutputIndexArray: number[],
    changeSatoshi: number,
    expected
) {
    const txContext = {
        tx: tx,
        inputIndex: inputIndex,
        inputSatoshis: inputSatoshis,
    }

    let inputTokenAddressArray = Buffer.alloc(0)
    let inputTokenAmountArray = Buffer.alloc(0)
    let tokenTxHeaderArray = Buffer.alloc(0)
    let tokenTxHashProofArray = Buffer.alloc(0)
    let tokenTxSatoshisBytesArray = Buffer.alloc(0)
    let tokenScriptBuf
    for (let i = 0; i < tokenTxArray.length; i++) {
        const tokenTx = tokenTxArray[i]

        // get token address and amount
        tokenScriptBuf =
            tokenTx.outputs[tokenOutputIndexArray[i]].script.toBuffer()
        const tokenScriptHex = tokenScriptBuf.toString('hex')
        const address = TokenProto.getTokenAddress(
            tokenScriptHex,
            BigInt(tokenScriptBuf.length)
        )
        inputTokenAddressArray = Buffer.concat([
            inputTokenAddressArray,
            Buffer.from(address, 'hex'),
        ])
        const amount = TokenProto.getTokenAmount(
            tokenScriptHex,
            BigInt(tokenScriptBuf.length)
        )
        const amountBuf = Buffer.alloc(8, 0)
        amountBuf.writeBigUInt64LE(BigInt(amount))
        inputTokenAmountArray = Buffer.concat([
            inputTokenAmountArray,
            amountBuf,
        ])

        // get token merkle res
        const proof = Common.getTxOutputProof(tokenTx, tokenOutputIndexArray[i])
        tokenTxHeaderArray = Buffer.concat([
            tokenTxHeaderArray,
            Buffer.from(proof.txHeader, 'hex'),
        ])
        const hashProofBuf = Buffer.from(proof.hashProof, 'hex')
        tokenTxHashProofArray = Buffer.concat([
            tokenTxHashProofArray,
            Common.getUInt32Buf(hashProofBuf.length),
            hashProofBuf,
        ])
        tokenTxSatoshisBytesArray = Buffer.concat([
            tokenTxSatoshisBytesArray,
            Buffer.from(proof.satoshiBytes, 'hex'),
        ])
    }

    const tokenOutputSatoshis = tx.outputs[0].satoshis

    const preimage = getPreimage(
        tx,
        transferCheck.lockingScript.subScript(0),
        inputSatoshis,
        inputIndex,
        sigtype
    )

    const unlockingScript = transferCheck.unlock(
        SigHashPreimage(toHex(preimage)),
        Bytes(prevouts.toString('hex')),
        Bytes(tokenScriptBuf.toString('hex')),
        Bytes(tokenTxHeaderArray.toString('hex')),
        Bytes(tokenTxHashProofArray.toString('hex')),
        Bytes(tokenTxSatoshisBytesArray.toString('hex')),
        Bytes(inputTokenAddressArray.toString('hex')),
        Bytes(inputTokenAmountArray.toString('hex')),
        tokenOutputSatoshis,
        changeSatoshi,
        Ripemd160(address1.hashBuffer.toString('hex')),
        Bytes('')
    )
    const result = unlockingScript.verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function unlockContractCheck(
    tx: mvc.Transaction,
    prevouts: Buffer,
    unlockContractCheck,
    inputIndex: number,
    tokenTxArray: mvc.Transaction[],
    tokenTxOutputIndexArray: number[],
    outputTokenIndexes: number[], // current tx token output index
    expected,
    fakeOtherOutput
) {
    const txContext = {
        tx: tx,
        inputIndex: inputIndex,
        inputSatoshis: inputSatoshis,
    }

    let inputTokenAddressArray = Buffer.alloc(0)
    let inputTokenAmountArray = Buffer.alloc(0)
    let tokenTxHeaderArray = Buffer.alloc(0)
    let tokenTxHashProofArray = Buffer.alloc(0)
    let tokenTxSatoshisBytesArray = Buffer.alloc(0)
    let tokenScriptBuf
    for (let i = 0; i < tokenTxArray.length; i++) {
        const tokenTx = tokenTxArray[i]

        // get token address and amount
        tokenScriptBuf =
            tokenTx.outputs[tokenTxOutputIndexArray[i]].script.toBuffer()
        const tokenScriptHex = tokenScriptBuf.toString('hex')
        const address = TokenProto.getTokenAddress(
            tokenScriptHex,
            BigInt(tokenScriptBuf.length)
        )
        inputTokenAddressArray = Buffer.concat([
            inputTokenAddressArray,
            Buffer.from(address, 'hex'),
        ])
        const amount = TokenProto.getTokenAmount(
            tokenScriptHex,
            BigInt(tokenScriptBuf.length)
        )
        const amountBuf = Buffer.alloc(8, 0)
        amountBuf.writeBigUInt64LE(BigInt(amount))
        inputTokenAmountArray = Buffer.concat([
            inputTokenAmountArray,
            amountBuf,
        ])

        // get token merkle res
        const proof = Common.getTxOutputProof(
            tokenTx,
            tokenTxOutputIndexArray[i]
        )
        tokenTxHeaderArray = Buffer.concat([
            tokenTxHeaderArray,
            Buffer.from(proof.txHeader, 'hex'),
        ])
        const hashProofBuf = Buffer.from(proof.hashProof, 'hex')
        tokenTxHashProofArray = Buffer.concat([
            tokenTxHashProofArray,
            Common.getUInt32Buf(hashProofBuf.length),
            hashProofBuf,
        ])
        tokenTxSatoshisBytesArray = Buffer.concat([
            tokenTxSatoshisBytesArray,
            Buffer.from(proof.satoshiBytes, 'hex'),
        ])
    }

    let otherOutputArray = Buffer.alloc(0)
    let tokenOutputIndexArray = Buffer.alloc(0)
    let j = 0
    const nOutputs = tx.outputs.length
    let tokenOutputSatoshis = inputSatoshis
    for (let i = 0; i < nOutputs; i++) {
        const tokenOutIndex = outputTokenIndexes[j]
        if (i == tokenOutIndex) {
            tokenOutputIndexArray = Buffer.concat([
                tokenOutputIndexArray,
                Common.getUInt32Buf(tokenOutIndex),
            ])
            j++
            tokenOutputSatoshis = tx.outputs[tokenOutIndex].satoshis
        } else {
            const output = tx.outputs[i]
            const outputBuf = Common.buildOutput(
                output.script.toBuffer(),
                output.satoshis
            )
            if (fakeOtherOutput === true) {
                otherOutputArray = Buffer.concat([otherOutputArray, outputBuf])
            } else {
                otherOutputArray = Buffer.concat([
                    otherOutputArray,
                    Common.getUInt32Buf(outputBuf.length),
                    outputBuf,
                ])
            }
        }
    }

    const preimage = getPreimage(
        tx,
        unlockContractCheck.lockingScript.subScript(0),
        inputSatoshis,
        inputIndex,
        sigtype
    )

    const result = unlockContractCheck
        .unlock(
            SigHashPreimage(toHex(preimage)),
            Bytes(prevouts.toString('hex')),
            Bytes(tokenScriptBuf.toString('hex')),
            Bytes(tokenTxHeaderArray.toString('hex')),
            Bytes(tokenTxHashProofArray.toString('hex')),
            Bytes(tokenTxSatoshisBytesArray.toString('hex')),
            Bytes(inputTokenAddressArray.toString('hex')),
            Bytes(inputTokenAmountArray.toString('hex')),
            nOutputs,
            Bytes(tokenOutputIndexArray.toString('hex')),
            tokenOutputSatoshis,
            Bytes(otherOutputArray.toString('hex'))
        )
        .verify(txContext)
    if (expected === true) {
        expect(result.success, result.error).to.be.true
    } else {
        expect(result.success, result.error).to.be.false
    }
}

function createTokenTx(tokenContract) {
    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    addInput(
        tx,
        dummyTxId,
        0,
        mvc.Script.buildPublicKeyHashOut(address1),
        inputSatoshis,
        [],
        true
    )
    tx.addOutput(
        new mvc.Transaction.Output({
            script: tokenContract.lockingScript,
            satoshis: inputSatoshis,
        })
    )
    return tx
}

function createInputTokenTx(tokenContract, prevTx: mvc.Transaction) {
    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    addInput(tx, prevTx.id, 0, prevTx.outputs[0].script, inputSatoshis, [])
    tx.addOutput(
        new mvc.Transaction.Output({
            script: tokenContract.lockingScript,
            satoshis: inputSatoshis,
        })
    )
    return tx
}

function verifyTokenTransfer(
    nTokenInputs: number,
    nTokenOutputs: number,
    nSatoshiInput: number,
    changeSatoshi: number,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    options: any = {}
) {
    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    if (options.wrongVersion) {
        tx.version = 1
    }
    let prevouts: any = []

    let sumInputTokens = BigInt(0)
    const tokenInstance: any = []
    const tokenTxs: any = []
    const prevTokenTxs: any = []
    const tokenOutputIndexArray: number[] = []
    const outputAmount = BigInt(1000)
    // add token input
    for (let i = 0; i < nTokenInputs; i++) {
        const token = createTokenContract(
            address1.hashBuffer,
            outputAmount + BigInt(i)
        )
        const prevTokenTx = createTokenTx(token)
        const tokenTx = createInputTokenTx(token, prevTokenTx)
        tokenInstance.push(token)
        tokenTxs.push(tokenTx)
        tokenOutputIndexArray.push(0)
        prevTokenTxs.push(prevTokenTx)
        sumInputTokens += outputAmount + BigInt(i)

        addInput(
            tx,
            tokenTx.id,
            0,
            token.lockingScript,
            inputSatoshis,
            prevouts
        )
    }

    // add mvc input
    for (let i = 0; i < nSatoshiInput; i++) {
        addInput(
            tx,
            dummyTxId,
            0,
            mvc.Script.buildPublicKeyHashOut(address1),
            inputSatoshis,
            prevouts
        )
    }

    if (options.outputTokenAdd !== undefined) {
        sumInputTokens += options.outputTokenAdd
    }

    const outputTokenArray: any = []
    for (let i = 0; i < nTokenOutputs; i++) {
        if (i == nTokenOutputs - 1) {
            outputTokenArray.push(sumInputTokens)
        } else {
            sumInputTokens -= BigInt(i + 1)
            outputTokenArray.push(BigInt(i + 1))
        }
    }

    // add tokenTransferCheckContract
    let tid = tokenID
    if (options.wrongTokenID) {
        tid = tokenID2
    }
    let tcHash = tokenCodeHash
    if (options.wrongTokenCodeHash) {
        tcHash = Buffer.alloc(20, 0)
    }

    let routeNTokenInputs = nTokenInputs
    if (options.wrongNSenders) {
        routeNTokenInputs = nTokenInputs - 1
    }

    let amountCheckRes
    if (options.wrongTransferCheck) {
        amountCheckRes = createUnlockContractCheck(
            [0],
            1,
            [outputAmount],
            [address1.hashBuffer]
        )
    } else {
        amountCheckRes = createTransferCheckContract(
            routeNTokenInputs,
            nTokenOutputs,
            outputTokenArray,
            (tid = tid),
            (tcHash = tcHash)
        )
    }
    const amountCheck = amountCheckRes.amountCheck
    const amountCheckTx = amountCheckRes.amountCheckTx
    addInput(
        tx,
        amountCheckTx.id,
        0,
        amountCheck.lockingScript,
        inputSatoshis,
        prevouts
    )

    let amountCheckInputIndex = tx.inputs.length - 1
    if (options.wrongAmountCheckInputIndex) {
        amountCheckInputIndex -= 1
    }

    prevouts = Buffer.concat(prevouts)

    // output
    const tokenScriptBuf = tokenInstance[0].lockingScript.toBuffer()
    const tokenScriptHex = tokenScriptBuf.toString('hex')
    for (let i = 0; i < nTokenOutputs; i++) {
        const scriptBuf = TokenProto.getNewTokenScript(
            tokenScriptHex,
            BigInt(tokenScriptBuf.length),
            address2.hashBuffer.toString('hex'),
            outputTokenArray[i]
        )
        addOutput(
            tx,
            mvc.Script.fromBuffer(Buffer.from(scriptBuf, 'hex')),
            inputSatoshis
        )
    }

    if (changeSatoshi > 0) {
        addOutput(tx, mvc.Script.buildPublicKeyHashOut(address1), changeSatoshi)
    }

    //console.log('outputTokenArray:', outputTokenArray)
    for (let i = 0; i < nTokenInputs; i++) {
        let tokenExpected = options.tokenExpected
        if (typeof options.tokenExpected === 'object') {
            tokenExpected = options.tokenExpected[i]
        }
        const pubKeyHex = toHex(privateKey.publicKey)
        const sigHex = toHex(
            signTx(
                tx,
                privateKey,
                tokenInstance[i].lockingScript,
                inputSatoshis,
                i,
                sigtype
            )
        )
        unlockTokenContract(
            tx,
            prevouts,
            tokenInstance[i],
            i,
            i,
            tokenTxs[i],
            0,
            0,
            prevTokenTxs[i],
            0,
            amountCheckHashIndex,
            amountCheckInputIndex,
            amountCheckTx,
            0,
            0,
            '',
            0,
            pubKeyHex,
            sigHex,
            Number(TokenProto.OP_TRANSFER),
            tokenExpected,
            options
        )
    }

    if (options.wrongTransferCheck !== true) {
        unlockTransferCheck(
            tx,
            prevouts,
            amountCheck,
            amountCheckInputIndex,
            tokenTxs,
            tokenOutputIndexArray,
            changeSatoshi,
            options.checkExpected
        )
    }
}

function unlockTokenContract(
    tx: mvc.Transaction,
    prevouts: Buffer,
    token,
    inputIndex: number,
    tokenInputIndex: number,
    tokenTx: mvc.Transaction,
    tokenTxOutputIndex: number,
    prevTokenInputIndex: number,
    prevTokenTx: mvc.Transaction,
    prevTokenOutputIndex: number,
    amountCheckHashIndex: number,
    amountCheckInputIndex: number,
    amountCheckTx: mvc.Transaction,
    amountCheckOutputIndex: number,
    contractInputIndex: number,
    contractTx,
    contractOutputIndex: number,
    pubKeyHex: string,
    sigHex: string,
    op: number,
    expected,
    options: any = {}
) {
    const preimage = getPreimage(
        tx,
        token.lockingScript,
        inputSatoshis,
        inputIndex,
        sigtype
    )

    const amountCheckScriptBuf =
        amountCheckTx.outputs[amountCheckOutputIndex].script.toBuffer()
    const amountCheckTxOutputProofInfo = Common.getTxOutputProof(
        amountCheckTx,
        amountCheckOutputIndex
    )
    const inputRes = Common.getTxInputProof(tokenTx, prevTokenInputIndex)
    let tokenTxInputProof = inputRes.inputProofInfo
    if (options.wrongTxProof == true) {
        const inputRes = Common.getTxInputProof(
            prevTokenTx,
            prevTokenInputIndex
        )
        tokenTxInputProof = inputRes.inputProofInfo
    }
    const tokenTxHeader = inputRes.txHeader
    const prevTokenTxOutputProofInfo = Common.getTxOutputProof(
        prevTokenTx,
        prevTokenOutputIndex
    )

    let contractTxOutputProof = Common.getEmptyTxOutputProof()
    if (op == Number(TokenProto.OP_UNLOCK_FROM_CONTRACT)) {
        contractTxOutputProof = Common.getTxOutputProof(
            contractTx,
            contractOutputIndex
        )
    }

    let prevTokenAddress = Bytes('')
    let prevTokenAmount = BigInt(0)
    const scriptBuf =
        prevTokenTx.outputs[prevTokenOutputIndex].script.toBuffer()
    const scriptHex = scriptBuf.toString('hex')
    if (scriptBuf.length > TokenProto.DATA_LEN) {
        prevTokenAddress = Bytes(
            TokenProto.getTokenAddress(scriptHex, BigInt(scriptBuf.length))
        )
        prevTokenAmount = TokenProto.getTokenAmount(
            scriptHex,
            BigInt(scriptBuf.length)
        )
    }

    const txContext = {
        tx: tx,
        inputIndex: inputIndex,
        inputSatoshis: inputSatoshis,
    }

    const unlockingScript = token.unlock(
        SigHashPreimage(toHex(preimage)),
        Bytes(prevouts.toString('hex')),
        // amountCheck
        tokenInputIndex,
        amountCheckHashIndex,
        amountCheckInputIndex,
        amountCheckTxOutputProofInfo,
        Bytes(amountCheckScriptBuf.toString('hex')),
        // token
        prevTokenInputIndex,
        prevTokenAddress,
        prevTokenAmount,
        // tokenTx input proof
        tokenTxHeader,
        tokenTxInputProof,
        // prevTokenTx output proof
        prevTokenTxOutputProofInfo,
        // sig data
        PubKey(pubKeyHex),
        Sig(sigHex),
        // contract
        contractInputIndex,
        contractTxOutputProof,
        op
    )
    const result = unlockingScript.verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createTokenSellContract(sellSatoshis: number) {
    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    addInput(
        tx,
        dummyTxId,
        0,
        mvc.Script.buildPublicKeyHashOut(address1),
        inputSatoshis,
        []
    )
    const tokenSell = new TokenSell(
        Ripemd160(address1.hashBuffer.toString('hex')),
        BigInt(sellSatoshis)
    )
    const data = Buffer.alloc(4, 0)
    const scriptData = Common.buildScriptData(data)
    tokenSell.setDataPartInASM(scriptData.toString('hex'))
    const sellScript = tokenSell.lockingScript
    tx.addOutput(
        new mvc.Transaction.Output({
            script: sellScript,
            satoshis: inputSatoshis,
        })
    )

    return { tokenSell, tokenSellTx: tx }
}

function unlockFromContract(
    nTokenInputs: number,
    nTokenOutputs: number,
    nOtherOutputs: number,
    options
) {
    const checkExpected = options.checkExpected
    const sellSatoshis = 10000
    let prevouts: any = []
    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION

    const { tokenSell, tokenSellTx } = createTokenSellContract(sellSatoshis)
    let scriptHash = Buffer.from(
        Common.getScriptHashBuf(tokenSell.lockingScript.toBuffer())
    )
    if (options.scriptHash) {
        scriptHash = options.scriptHash
    }
    const contractTx = tokenSellTx
    const contractInputIndex = 0

    addInput(
        tx,
        tokenSellTx.id,
        0,
        tokenSell.lockingScript,
        inputSatoshis,
        prevouts
    )

    const tokenInstance: any = []
    let tokenScript
    const tokenInputIndexArray: any = []
    const tokenTxs: any = []
    const prevTokenTxs: any = []
    let sumInputTokenAmount = BigInt(0)
    const tokenTxOutputIndexArray: number[] = []
    for (let i = 0; i < nTokenInputs; i++) {
        const inputTokenAmount = BigInt(sellSatoshis * 10)
        let address
        if (Array.isArray(scriptHash)) {
            address = scriptHash[i]
        } else {
            address = scriptHash
        }
        const token = createTokenContract(address, inputTokenAmount)
        const prevTokenTx = createTokenTx(token)
        const tokenTxHeader = createInputTokenTx(token, prevTokenTx)
        tokenInstance.push(token)
        tokenTxs.push(tokenTxHeader)
        tokenTxOutputIndexArray.push(0)
        prevTokenTxs.push(prevTokenTx)

        tokenInputIndexArray.push(i + 1)
        sumInputTokenAmount += inputTokenAmount

        addInput(
            tx,
            tokenTxHeader.id,
            0,
            token.lockingScript,
            inputSatoshis,
            prevouts
        )
        tokenScript = token.lockingScript
    }

    const outputTokenAddress: any = []
    const outputTokenArray: any = []
    for (let i = 0; i < nTokenOutputs; i++) {
        outputTokenAddress.push(address2.hashBuffer)
        if (i == nTokenOutputs - 1) {
            if (options.outputTokenAdd !== undefined) {
                outputTokenArray.push(
                    sumInputTokenAmount + options.outputTokenAdd
                )
            } else {
                outputTokenArray.push(sumInputTokenAmount)
            }
        } else {
            outputTokenArray.push(BigInt(1))
            sumInputTokenAmount -= BigInt(1)
        }
    }
    let tid = tokenID
    if (options.wrongTokenID) {
        tid = tokenID2
    }
    let tcHash = tokenCodeHash
    if (options.wrongTokenCodeHash) {
        tcHash = Buffer.alloc(20, 0)
    }

    if (options.wrongNSenders) {
        tokenInputIndexArray.pop()
    }
    const { amountCheck, amountCheckTx } = createUnlockContractCheck(
        tokenInputIndexArray,
        nTokenOutputs,
        outputTokenArray,
        outputTokenAddress,
        tid,
        tcHash
    )
    addInput(
        tx,
        amountCheckTx.id,
        0,
        amountCheck.lockingScript,
        inputSatoshis,
        prevouts
    )
    const amountCheckInputIndex = tx.inputs.length - 1

    prevouts = Buffer.concat(prevouts)

    for (let i = 0; i < nOtherOutputs; i++) {
        addOutput(tx, mvc.Script.buildPublicKeyHashOut(address1), sellSatoshis)
    }

    const outputTokenIndexArray: any = []
    for (let i = 0; i < nTokenOutputs; i++) {
        const tokenScriptBuffer = TokenProto.getNewTokenScript(
            tokenScript.toHex(),
            BigInt(tokenScript.toBuffer().length),
            outputTokenAddress[i].toString('hex'),
            outputTokenArray[i]
        )
        addOutput(
            tx,
            mvc.Script.fromBuffer(Buffer.from(tokenScriptBuffer, 'hex')),
            inputSatoshis
        )
        outputTokenIndexArray.push(i + nOtherOutputs)
    }
    unlockContractCheck(
        tx,
        prevouts,
        amountCheck,
        amountCheckInputIndex,
        tokenTxs,
        tokenTxOutputIndexArray,
        outputTokenIndexArray,
        checkExpected,
        options.fakeOtherOutput
    )

    if (options.wrongLockContractTx) {
        tokenSellTx.nLockTime = 1
    }

    const pubKeyHex = Buffer.alloc(33, 0).toString('hex')
    const sigHex = Buffer.alloc(72, 0).toString('hex')
    for (let i = 0; i < nTokenInputs; i++) {
        const op = options.op || TokenProto.OP_UNLOCK_FROM_CONTRACT
        let tokenExpected = options.tokenExpected
        if (typeof tokenExpected === 'object') {
            tokenExpected = options.tokenExpected[i]
        }

        unlockTokenContract(
            tx,
            prevouts,
            tokenInstance[i],
            i + 1,
            i,
            tokenTxs[i],
            0,
            0,
            prevTokenTxs[i],
            0,
            amountCheckHashIndex,
            amountCheckInputIndex,
            amountCheckTx,
            0,
            contractInputIndex,
            contractTx,
            0,
            pubKeyHex,
            sigHex,
            op,
            tokenExpected
        )
    }
}

function unlockFromGenesis(options: any = {}) {
    const genesis = Utils.createGenesisContract(
        Genesis,
        issuerAddress,
        Buffer.alloc(36, 0)
    )

    const genesisScript = genesis.lockingScript.toBuffer()

    let prevGenesisTx = new mvc.Transaction()
    prevGenesisTx.version = Common.TX_VERSION
    addInput(
        prevGenesisTx,
        dummyTxId,
        0,
        mvc.Script.buildPublicKeyHashOut(address1),
        inputSatoshis,
        []
    )
    addOutput(prevGenesisTx, genesisScript, inputSatoshis)

    // create genesisTx
    let genesisTx = new mvc.Transaction()
    genesisTx.version = Common.TX_VERSION
    addInput(
        genesisTx,
        prevGenesisTx.id,
        0,
        genesis.lockingScript,
        inputSatoshis,
        []
    )

    // create genesis output
    const genesisTxid = Common.genGenesisTxid(prevGenesisTx.id, 0)
    const newGenesisScript = TokenProto.getNewGenesisScript(
        genesisScript.toString('hex'),
        BigInt(genesisScript.length),
        genesisTxid
    )
    addOutput(genesisTx, mvc.Script.fromHex(newGenesisScript), inputSatoshis)

    const tokenAmount = BigInt(10000)
    let genesisHash = Common.getScriptHashBuf(
        Buffer.from(newGenesisScript, 'hex')
    )
    if (options.wrongGenesisHash) {
        genesisHash = Buffer.alloc(20, 0)
    }

    // create token output
    const token = Utils.createTokenContract(
        Token,
        address1.hashBuffer,
        tokenAmount,
        genesisHash,
        Buffer.from(genesisTxid, 'hex'),
        transferCheckCodeHashArray,
        unlockContractCodeHashArray
    )
    addOutput(genesisTx, token.lockingScript, inputSatoshis)

    const tokenID = Buffer.from(
        TokenProto.getTokenID(
            token.lockingScript.toHex(),
            BigInt(token.lockingScript.length)
        ),
        'hex'
    )

    let tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    let prevouts: any = []

    addInput(tx, genesisTx.id, 1, token.lockingScript, inputSatoshis, prevouts)

    const { amountCheck, amountCheckTx } = createTransferCheckContract(
        1,
        1,
        [tokenAmount],
        tokenID,
        tokenCodeHash
    )

    addInput(
        tx,
        amountCheckTx.id,
        0,
        amountCheck.lockingScript,
        inputSatoshis,
        prevouts
    )

    prevouts = Buffer.concat(prevouts)

    addOutput(tx, token.lockingScript, inputSatoshis)

    const amountCheckInputIndex = 1
    const pubKeyHex = toHex(privateKey.publicKey)
    let sigHex = toHex(
        signTx(tx, privateKey, token.lockingScript, inputSatoshis, 0, sigtype)
    )

    // unlock by genesisTxid
    unlockTokenContract(
        tx,
        prevouts,
        token,
        0,
        0,
        genesisTx,
        1,
        0,
        prevGenesisTx,
        0,
        amountCheckHashIndex,
        amountCheckInputIndex,
        amountCheckTx,
        0,
        0,
        '',
        0,
        pubKeyHex,
        sigHex,
        Number(TokenProto.OP_TRANSFER),
        true
    )

    // unlock by genesisHash
    tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    addInput(
        tx,
        genesisTx.id,
        0,
        mvc.Script.fromHex(newGenesisScript),
        inputSatoshis,
        []
    )

    addOutput(tx, mvc.Script.fromHex(newGenesisScript), inputSatoshis)
    addOutput(tx, token.lockingScript, inputSatoshis)

    prevGenesisTx = genesisTx
    genesisTx = tx

    tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    prevouts = []
    addInput(tx, genesisTx.id, 1, token.lockingScript, inputSatoshis, prevouts)

    addInput(
        tx,
        amountCheckTx.id,
        0,
        amountCheck.lockingScript,
        inputSatoshis,
        prevouts
    )

    prevouts = Buffer.concat(prevouts)

    addOutput(tx, token.lockingScript, inputSatoshis)

    sigHex = toHex(
        signTx(tx, privateKey, token.lockingScript, inputSatoshis, 0, sigtype)
    )
    // unlock by genesisHash
    unlockTokenContract(
        tx,
        prevouts,
        token,
        0,
        0,
        genesisTx,
        1,
        0,
        prevGenesisTx,
        0,
        amountCheckHashIndex,
        amountCheckInputIndex,
        amountCheckTx,
        0,
        0,
        '',
        0,
        pubKeyHex,
        sigHex,
        Number(TokenProto.OP_TRANSFER),
        options.expected
    )
}

function unlockFromFakeGenesis(options: any = {}) {
    const genesis = Utils.createGenesisContract(
        Genesis,
        issuerAddress,
        Buffer.alloc(36, 0)
    )

    const genesisScript = genesis.lockingScript.toBuffer()

    const prevGenesisTx = new mvc.Transaction()
    prevGenesisTx.version = Common.TX_VERSION
    addInput(
        prevGenesisTx,
        dummyTxId,
        0,
        mvc.Script.buildPublicKeyHashOut(address1),
        inputSatoshis,
        []
    )
    addOutput(prevGenesisTx, genesisScript, inputSatoshis)
    // add fake genesis
    addOutput(
        prevGenesisTx,
        mvc.Script.buildPublicKeyHashOut(address1),
        inputSatoshis - 1000
    )

    // create genesisTx
    const genesisTx = new mvc.Transaction()
    genesisTx.version = Common.TX_VERSION
    // use fake genesisTxid
    addInput(
        genesisTx,
        prevGenesisTx.id,
        1,
        mvc.Script.buildPublicKeyHashOut(address1),
        inputSatoshis - 1000,
        []
    )

    // create genesis output
    const genesisTxid = Common.genGenesisTxid(prevGenesisTx.id, 0)
    const newGenesisScript = TokenProto.getNewGenesisScript(
        genesisScript.toString('hex'),
        BigInt(genesisScript.length),
        genesisTxid
    )
    addOutput(genesisTx, mvc.Script.fromHex(newGenesisScript), inputSatoshis)

    const tokenAmount = BigInt(10000)
    let genesisHash = Common.getScriptHashBuf(
        Buffer.from(newGenesisScript, 'hex')
    )
    if (options.wrongGenesisHash) {
        genesisHash = Buffer.alloc(20, 0)
    }

    // create token output
    const token = Utils.createTokenContract(
        Token,
        address1.hashBuffer,
        tokenAmount,
        genesisHash,
        Buffer.from(genesisTxid, 'hex'),
        transferCheckCodeHashArray,
        unlockContractCodeHashArray
    )
    addOutput(genesisTx, token.lockingScript, inputSatoshis)

    const tokenID = Buffer.from(
        TokenProto.getTokenID(
            token.lockingScript.toHex(),
            BigInt(token.lockingScript.toBuffer().length)
        ),
        'hex'
    )

    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    let prevouts: any = []

    addInput(tx, genesisTx.id, 1, token.lockingScript, inputSatoshis, prevouts)

    const { amountCheck, amountCheckTx } = createTransferCheckContract(
        1,
        1,
        [tokenAmount],
        tokenID,
        tokenCodeHash
    )

    addInput(
        tx,
        amountCheckTx.id,
        0,
        amountCheck.lockingScript,
        inputSatoshis,
        prevouts
    )

    prevouts = Buffer.concat(prevouts)

    addOutput(tx, token.lockingScript, inputSatoshis)

    const amountCheckInputIndex = 1
    const pubKeyHex = toHex(privateKey.publicKey)
    const sigHex = toHex(
        signTx(tx, privateKey, token.lockingScript, inputSatoshis, 0, sigtype)
    )

    // unlock by genesisTxid
    unlockTokenContract(
        tx,
        prevouts,
        token,
        0,
        0,
        genesisTx,
        1,
        0,
        prevGenesisTx,
        1,
        amountCheckHashIndex,
        amountCheckInputIndex,
        amountCheckTx,
        0,
        0,
        '',
        0,
        pubKeyHex,
        sigHex,
        Number(TokenProto.OP_TRANSFER),
        options.expected
    )
}

describe('Test token contract unlock In Javascript', () => {
    before(() => {
        initContractHash()
    })

    it('t1: should succeed with multi input and output', () => {
        const options = {
            tokenExpected: true,
            checkExpected: true,
        }
        for (let i = 1; i <= 3; i++) {
            for (let j = 1; j <= 3; j++) {
                verifyTokenTransfer(i, j, 0, 0, options)
            }
        }
        verifyTokenTransfer(maxInputLimit, maxOutputLimit, 0, 0, options)
    })

    it('t2: should succeed with mvc input', () => {
        const options = {
            tokenExpected: true,
            checkExpected: true,
        }
        for (let i = 1; i <= 3; i++) {
            for (let j = 1; j <= 3; j++) {
                //console.log("verify token contract:", i, j)
                verifyTokenTransfer(i, j, 2, 1000, options)
            }
        }
        verifyTokenTransfer(maxInputLimit, maxOutputLimit, 2, 1000, options)
    })

    it('t3: should failed because token input number is greater than transferCheck nSenders', () => {
        const options = {
            tokenExpected: [true, false],
            checkExpected: false,
            wrongNSenders: true,
        }
        verifyTokenTransfer(2, 1, 0, 0, options)
    })

    it('t4: should failed because token input is greater than maxInputLimit', () => {
        const options = {
            tokenExpected: true,
            checkExpected: false,
        }
        verifyTokenTransfer(maxInputLimit + 1, 1, 0, 0, options)
    })

    it('t5: should failed because token output is greater than maxOutputLimit', () => {
        const options = {
            tokenExpected: true,
            checkExpected: false,
        }
        verifyTokenTransfer(1, maxOutputLimit + 1, 0, 0, options)
    })

    it('t6: should failed because input amount is greater then output amount', () => {
        const options = {
            tokenExpected: true,
            checkExpected: false,
            outputTokenAdd: BigInt(100),
        }
        verifyTokenTransfer(1, 1, 0, 0, options)
    })

    it('t7: should failed because input amount is less than output amount', () => {
        const options = {
            tokenExpected: true,
            checkExpected: false,
            outputTokenAdd: BigInt(-100),
        }
        verifyTokenTransfer(1, 1, 0, 0, options)
    })

    it('t8: should failed with wrong tokenID in routeAmountCheck', () => {
        const options = {
            tokenExpected: false,
            checkExpected: false,
            wrongTokenID: true,
        }
        verifyTokenTransfer(1, 1, 0, 0, options)
    })

    it('t9: should failed with wrong token code hash in routeAmountCheck', () => {
        const options = {
            tokenExpected: false,
            checkExpected: false,
            wrongTokenCodeHash: true,
        }
        verifyTokenTransfer(1, 1, 0, 0, options)
    })

    it('t010: should failed when token is unlock from wrong tokenTransferCheck', () => {
        verifyTokenTransfer(1, 1, 0, 0, {
            tokenExpected: false,
            wrongTransferCheck: true,
        })
    })

    it('t011: should succeed when token is generated from genesis', () => {
        unlockFromGenesis()
    })

    it('t012: should failed when token is unlock from wrong genesis', () => {
        unlockFromGenesis({ wrongGenesisHash: true, expected: false })
    })

    it('t013: should failed when token is unlock from wrong amountCheckInputIndex', () => {
        verifyTokenTransfer(1, 1, 0, 0, {
            tokenExpected: false,
            wrongAmountCheckInputIndex: true,
        })
    })

    it('t014: it should succeed when unlock from contract', () => {
        const options = {
            tokenExpected: true,
            checkExpected: true,
        }
        for (let i = 1; i <= 2; i++) {
            for (let j = 1; j <= 3; j++) {
                unlockFromContract(i, j, 2, options)
            }
        }
        unlockFromContract(1, 1, 2, options)
    })

    it('t015: it should failed when unlock from contract with wrong tokenInputIndex', () => {
        const options = {
            tokenExpected: [true, false],
            checkExpected: false,
            wrongNSenders: true,
        }
        unlockFromContract(2, 1, 1, options)
    })

    it('t016: it should success when burn token', () => {
        const options = {
            tokenExpected: true,
            checkExpected: true,
            scriptHash: Buffer.alloc(20, 0),
        }
        unlockFromContract(2, 0, 1, options)
    })

    it('t017: it should failed when not all token inputs is in burning address', () => {
        const options = {
            tokenExpected: [true, false],
            checkExpected: false,
            scriptHash: [Buffer.alloc(20, 0), Buffer.alloc(20, 1)],
        }
        unlockFromContract(2, 0, 1, options)
    })

    it('t018: it should failed when try to take burning address token', () => {
        const { tokenSell } = createTokenSellContract(10000)
        const scriptHash = Common.getScriptHashBuf(
            tokenSell.lockingScript.toBuffer()
        )
        const options = {
            tokenExpected: [true, true],
            checkExpected: false,
            scriptHash: [Buffer.alloc(20, 0), scriptHash],
        }
        unlockFromContract(2, 1, 1, options)
    })

    it('t019: it should failed when unlock from contract with wrong lockContractTx', () => {
        const options = {
            tokenExpected: false,
            checkExpected: true,
            wrongLockContractTx: true,
        }
        unlockFromContract(1, 1, 1, options)
    })

    it('t020: it should failed when unlock from contract with wrong contract script hash', () => {
        const options = {
            tokenExpected: false,
            checkExpected: true,
            scriptHash: address2.hashBuffer,
        }
        unlockFromContract(1, 1, 1, options)
    })

    it('t021: it should failed when unlock from contract with wrong tokenID', () => {
        const options = {
            tokenExpected: false,
            checkExpected: false,
            wrongTokenID: true,
        }
        unlockFromContract(1, 1, 1, options)
    })

    it('t022: it should failed when unlock from contract with wrong token code hash', () => {
        const options = {
            tokenExpected: false,
            checkExpected: false,
            wrongTokenCodeHash: true,
        }
        unlockFromContract(1, 1, 1, options)
    })

    it('t023: it should failed when input token amount less then output token amount', () => {
        const options = {
            tokenExpected: true,
            checkExpected: false,
            outputTokenAdd: BigInt(100),
        }
        unlockFromContract(1, 1, 1, options)
    })

    it('t024: it should failed when pass wrong op to token', () => {
        const options = {
            tokenExpected: false,
            checkExpected: true,
            op: 3,
        }
        unlockFromContract(1, 1, 1, options)
    })

    it('t025: should failed when fake many outputs into one output', () => {
        const options = {
            tokenExpected: true,
            checkExpected: false,
            fakeOtherOutput: true,
        }
        unlockFromContract(1, 1, 1, options)
    })

    it('t026: should failed when wrong tx version', () => {
        verifyTokenTransfer(1, 1, 0, 0, {
            wrongVersion: true,
            tokenExpected: false,
        })
    })

    it('t027: should failed when wrong tx proof', () => {
        verifyTokenTransfer(1, 1, 0, 0, {
            wrongTxProof: true,
            tokenExpected: false,
        })
    })

    it('t028: should failed when fake genesisTxid', () => {
        unlockFromFakeGenesis({ expected: false })
    })
})

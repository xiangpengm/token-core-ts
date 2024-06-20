import { bsv as mvc } from 'scrypt-ts'
import { Bytes, buildContractClass } from 'scryptlib'
import { readFileSync, existsSync } from 'fs'
import { Buffer } from 'node:buffer'
import * as path from 'path'

export const TX_VERSION = 10
export const SIG_HASH_ALL =
    mvc.crypto.Signature.SIGHASH_ALL | mvc.crypto.Signature.SIGHASH_FORKID
export const SIG_HASH_SINGLE =
    mvc.crypto.Signature.SIGHASH_SINGLE | mvc.crypto.Signature.SIGHASH_FORKID

export const dummyTxId =
    'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458'

export const toBufferLE = function (num: bigint, width: number) {
    const hex = num.toString(16)
    const buffer = Buffer.from(
        hex.padStart(width * 2, '0').slice(0, width * 2),
        'hex'
    )
    buffer.reverse()
    return buffer
}

export const toBigIntLE = function (buf: Buffer) {
    const reversed = Buffer.from(buf)
    reversed.reverse()
    const hex = reversed.toString('hex')
    if (hex.length === 0) {
        return BigInt(0)
    }
    return BigInt(`0x${hex}`)
}

export function loadReleaseDesc(fileName: string) {
    const filePath = path.join(__dirname, `../out/${fileName}`)
    if (!existsSync(filePath)) {
        throw new Error(
            `Description file ${filePath} not exist!\nIf You already run 'npm run watch', maybe fix the compile error first!`
        )
    }
    return JSON.parse(readFileSync(filePath).toString())
}

export const getUInt8Buf = function (amount: number) {
    const buf = Buffer.alloc(1, 0)
    buf.writeUInt8(amount)
    return buf
}

export const getUInt16Buf = function (amount: number) {
    const buf = Buffer.alloc(2, 0)
    buf.writeUInt16LE(amount)
    return buf
}

export const getUInt32Buf = function (index: number) {
    const buf = Buffer.alloc(4, 0)
    buf.writeUInt32LE(index)
    return buf
}

export const getUInt64Buf = function (amount: bigint | number) {
    const buf = Buffer.alloc(8, 0)
    buf.writeBigUInt64LE(BigInt(amount))
    return buf
}

export const getTxIdBuf = function (txid: string) {
    const buf = Buffer.from(txid, 'hex').reverse()
    return buf
}

export const writeVarint = function (buf: Buffer) {
    const n = buf.length

    let header = Buffer.alloc(0)
    if (n < 0xfd) {
        header = getUInt8Buf(n)
    } else if (n < 0x10000) {
        header = Buffer.concat([Buffer.from('fd', 'hex'), getUInt16Buf(n)])
    } else if (n < 0x100000000) {
        header = Buffer.concat([Buffer.from('fe', 'hex'), getUInt32Buf(n)])
    } else if (n < 0x10000000000000000) {
        header = Buffer.concat([Buffer.from('ff', 'hex'), getUInt64Buf(n)])
    }

    return Buffer.concat([header, buf])
}

export const buildOutput = function (
    outputScriptBuf: Buffer,
    outputSatoshis: number
) {
    return Buffer.concat([
        getUInt64Buf(outputSatoshis),
        writeVarint(outputScriptBuf),
    ])
}

export const addInput = function (
    tx: mvc.Transaction,
    prevTxId: string,
    prevTxOutputIndex: number,
    lockingScript,
    utxoSatoshis: number,
    prevouts: Buffer[],
    p2pkh = false
) {
    if (p2pkh === true) {
        tx.addInput(
            new mvc.Transaction.Input.PublicKeyHash({
                output: new mvc.Transaction.Output({
                    script: lockingScript,
                    satoshis: utxoSatoshis,
                }),
                prevTxId: prevTxId,
                outputIndex: prevTxOutputIndex,
                script: mvc.Script.empty(),
            })
        )
    } else {
        tx.addInput(
            new mvc.Transaction.Input({
                prevTxId: prevTxId,
                outputIndex: prevTxOutputIndex,
                script: '',
            }),
            lockingScript,
            utxoSatoshis
        )
    }
    prevouts.push(getTxIdBuf(prevTxId))
    prevouts.push(getUInt32Buf(prevTxOutputIndex))
}

export const addOutput = function (
    tx: mvc.Transaction,
    lockingScript,
    outputSatoshis: number
) {
    tx.addOutput(
        new mvc.Transaction.Output({
            script: lockingScript,
            satoshis: outputSatoshis,
        })
    )
    //console.log('addOutput: output:', tx.outputs.length, tx.outputs[tx.outputs.length-1].toBufferWriter().toBuffer().toString('hex'))
}

export const createScriptTx = function (
    mvcFeeTx: mvc.Transaction,
    mvcFeeOutputIndex: number,
    lockingScript,
    outputSatoshis: number,
    fee: number,
    changeAddress: mvc.Address,
    inputPrivKey: mvc.PrivateKey
) {
    const output = mvcFeeTx.outputs[mvcFeeOutputIndex]
    const tx = new mvc.Transaction()
    tx.version = TX_VERSION
    tx.addInput(
        new mvc.Transaction.Input.PublicKeyHash({
            output: new mvc.Transaction.Output({
                script: output.script,
                satoshis: output.satoshis,
            }),
            prevTxId: mvcFeeTx.id,
            outputIndex: mvcFeeOutputIndex,
            script: mvc.Script.empty(),
        })
    )
    const changeAmount = output.satoshis - fee - outputSatoshis
    tx.addOutput(
        new mvc.Transaction.Output({
            script: lockingScript,
            satoshis: outputSatoshis,
        })
    )
    tx.addOutput(
        new mvc.Transaction.Output({
            script: mvc.Script.buildPublicKeyHashOut(changeAddress),
            satoshis: changeAmount,
        })
    )

    // sign
    const sig = tx.inputs[0].getSignatures(tx, inputPrivKey, 0, SIG_HASH_ALL)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ipt = tx.inputs[0] as any
    ipt.addSignature(tx, sig[0])
    return tx
}

export const signP2PKH = function (
    tx: mvc.Transaction,
    privKey: mvc.PrivateKey,
    inputIndex: number
) {
    const sig = tx.inputs[inputIndex].getSignatures(
        tx,
        privKey,
        inputIndex,
        SIG_HASH_ALL
    )
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ipt = tx.inputs[inputIndex] as any
    ipt.addSignature(tx, sig[0])
}

export const bufToInt128 = function (buf: Buffer) {
    let amount
    const signByte = buf.readUInt8(15)
    // minus
    if (signByte >= 0x80) {
        const signBuf = Buffer.alloc(1, 0)
        signBuf.writeUInt8(signByte - 128)
        const sub = Buffer.concat([buf.subarray(0, 15), signBuf])
        amount = BigInt(-1) * toBigIntLE(sub)
    } else {
        amount = toBigIntLE(buf.subarray(0, 16))
    }
    return amount
}

export const int128ToBuf = function (amount: bigint) {
    let buf = Buffer.alloc(16, 0)
    if (amount >= BigInt(0)) {
        buf = toBufferLE(amount, 16)
    } else {
        amount = amount * BigInt(-1)
        if (amount > BigInt('0x008' + '0'.repeat(31))) {
            throw Error('amount is to large')
        }
        amount += BigInt('0x008' + '0'.repeat(31))
        buf = toBufferLE(amount, 16)
    }
    return buf
}

export const decodeOpPushData = function (scriptBuf: Buffer) {
    let len = 0
    let value = 0

    const header = scriptBuf.readUInt8()
    if (header < 1 || header > 78) {
        return { len, value }
    }

    if (header == 76) {
        len = 2
        value = scriptBuf.readUInt16LE(1)
    } else if (header == 77) {
        len = 3
        value = scriptBuf.readUInt16LE(1)
    } else if (header === 78) {
        len = 5
        value = scriptBuf.readUInt32LE(1)
    } else {
        len = 1
        value = header
    }
    return { len, value }
}

export const getOpPushDataLen = function (dataLen: number) {
    if (dataLen <= 75) {
        return 1
    } else if (dataLen <= 255) {
        return 2
    } else if (dataLen <= 65535) {
        return 3
    } else {
        return 5
    }
}

export const buildScriptData = function (data: Buffer) {
    const res = Buffer.concat([data, getUInt32Buf(0), getUInt8Buf(255)])
    const pushDataLen = getOpPushDataLen(res.length)
    res.writeUInt32LE(pushDataLen + data.length, data.length)
    return res
}

export const getOutpoint = function (txid: string, index: number) {
    return Buffer.concat([getTxIdBuf(txid), getUInt32Buf(index)])
}

export const genGenesisTxid = function (txid: string, index: number) {
    return Buffer.concat([getTxIdBuf(txid), getUInt32Buf(index)]).toString(
        'hex'
    )
}

export const buildOpReturnData = function (data: Buffer) {
    const length = data.length
    if (length <= 75) {
        return Buffer.concat([getUInt8Buf(length), data])
    } else if (length <= 255) {
        return Buffer.concat([
            Buffer.from('4c', 'hex'),
            getUInt8Buf(length),
            data,
        ])
    } else if (length <= 65535) {
        return Buffer.concat([
            Buffer.from('4d', 'hex'),
            getUInt16Buf(length),
            data,
        ])
    } else {
        return Buffer.concat([
            Buffer.from('4e', 'hex'),
            getUInt32Buf(length),
            data,
        ])
    }
}

export const getScriptHashBuf = function (script: Buffer) {
    const res = Buffer.from(mvc.crypto.Hash.sha256ripemd160(script))
    return res
}

export function getTxidInfo(tx: mvc.Transaction) {
    const writer = new mvc.encoding.BufferWriter()
    writer.writeUInt32LE(tx.version)
    writer.writeUInt32LE(tx.nLockTime)
    writer.writeUInt32LE(tx.inputs.length)
    writer.writeUInt32LE(tx.outputs.length)

    const inputWriter = new mvc.encoding.BufferWriter()
    const inputWriter2 = new mvc.encoding.BufferWriter()
    for (const input of tx.inputs) {
        inputWriter.writeReverse(input.prevTxId)
        inputWriter.writeUInt32LE(input.outputIndex)
        inputWriter.writeUInt32LE(input.sequenceNumber)

        inputWriter2.write(mvc.crypto.Hash.sha256(input.script.toBuffer()))
    }
    const inputHashProof = inputWriter.toBuffer()
    writer.write(mvc.crypto.Hash.sha256(inputHashProof))
    writer.write(mvc.crypto.Hash.sha256(inputWriter2.toBuffer()))

    const outputWriter = new mvc.encoding.BufferWriter()
    for (const output of tx.outputs) {
        outputWriter.writeUInt64LEBN(output.satoshisBN as unknown as number)
        outputWriter.write(mvc.crypto.Hash.sha256(output.script.toBuffer()))
    }
    const outputHashProof = outputWriter.toBuffer()
    writer.write(mvc.crypto.Hash.sha256(outputHashProof))

    const txHeader = writer.toBuffer().toString('hex')
    return {
        txHeader,
        inputHashProof: inputHashProof.toString('hex'),
        outputHashProof: outputHashProof.toString('hex'),
    }
}

export const getTxInputProof = function (
    tx: mvc.Transaction,
    inputIndex: number
) {
    const info = getTxidInfo(tx)
    const txHeader = Bytes(info.txHeader)
    const input = tx.inputs[inputIndex]
    const res = {
        hashProof: Bytes(info.inputHashProof),
        txHash: Bytes(Buffer.from(input.prevTxId).reverse().toString('hex')),
        outputIndexBytes: Bytes(
            getUInt32Buf(input.outputIndex).toString('hex')
        ),
        sequenceBytes: Bytes(
            getUInt32Buf(input.sequenceNumber).toString('hex')
        ),
    }
    return {
        inputProofInfo: res,
        txHeader,
    }
}

export const getTxOutputProof = function (
    tx: mvc.Transaction,
    outputIndex: number
) {
    const info = getTxidInfo(tx)
    const output = tx.outputs[outputIndex]
    const res = {
        txHeader: Bytes(info.txHeader),
        hashProof: Bytes(info.outputHashProof),
        satoshiBytes: Bytes(getUInt64Buf(output.satoshis).toString('hex')),
        scriptHash: Bytes(
            mvc.crypto.Hash.sha256(output.script.toBuffer()).toString('hex')
        ),
    }
    return res
}

export const getEmptyTxOutputProof = function () {
    const data = {
        txHeader: Bytes(''),
        hashProof: Bytes(''),
        satoshiBytes: Bytes(''),
        scriptHash: Bytes(''),
    }
    return data
}

export const getScriptData = function (scriptBuf: Buffer) {
    const dataLen = scriptBuf.readUInt32LE(scriptBuf.length - 5)
    return scriptBuf.subarray(scriptBuf.length - dataLen - 5)
}

function loadDesc(fileName) {
    const filePath = path.join(__dirname, `../../../artifacts/${fileName}`)
    if (!existsSync(filePath)) {
        throw new Error(
            `Description file ${filePath} not exist!\nIf You already run 'npm run watch', maybe fix the compile error first!`
        )
    }
    return JSON.parse(readFileSync(filePath).toString())
}

export const genContract = function (name: string) {
    return buildContractClass(loadDesc(name + '.json'))
}

export function genSensibleIdAndUniqueId(txId: string, outputIndex: number) {
    const sensibleId = Buffer.concat([
        Buffer.from([...Buffer.from(txId, 'hex')].reverse()),
        getUInt32Buf(outputIndex),
    ]).toString('hex')
    const uniqueId = mvc.crypto.Hash.sha256ripemd160(
        Buffer.concat([Buffer.from(sensibleId, 'hex')])
    ).toString('hex')
    return [sensibleId, uniqueId]
}

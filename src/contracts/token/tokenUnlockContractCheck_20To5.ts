import {
    method,
    assert,
    SmartContract,
    ByteString,
    prop,
    Utils,
    len,
    sha256,
    hash256,
    hash160,
    SigHash,
    slice,
    toByteString,
    Tx,
    SigHashPreimage,
} from 'scrypt-ts'
import { TxOutputProof, TxUtil } from '../txUtil'
import { ProtoHeader } from '../protoheader'
import { TokenProto } from './tokenProto'
import { AmountCheckProto } from './tokenAmountCheckProto'

export class TokenUnlockContractCheck20To5 extends SmartContract {
    @prop()
    static readonly MAX_INPUT: bigint = 20n
    @prop()
    static readonly MAX_OUTPUT: bigint = 5n

    @method()
    verifyOutput(
        output: ByteString,
        tokenScriptLen: bigint,
        tokenID: ByteString
    ): boolean {
        const b = slice(output, 8n)
        const n = Utils.fromLEUnsigned(slice(b, 0n, 1n))
        let sum = 0n
        let offset = 0n
        if (n < 0xfdn) {
            sum = 1n + n
            offset = 1n
        } else if (n == 0xfdn) {
            sum = 3n + Utils.fromLEUnsigned(slice(b, 1n, 3n))
            offset = 3n
        } else if (n == 0xfen) {
            sum = 5n + Utils.fromLEUnsigned(slice(b, 1n, 5n))
            offset = 5n
        } else {
            // not support 8 bytes length output
            assert(false)
        }
        // check if other output is the same token output
        assert(len(output) == sum + 8n)
        const script = slice(output, 8n + offset)
        if (tokenScriptLen == len(script)) {
            assert(TokenProto.getTokenID(script, tokenScriptLen) != tokenID)
        }
        return true
    }

    @method()
    public unlock(
        txPreimage: SigHashPreimage,
        prevouts: ByteString,
        tokenScript: ByteString,
        tokenTxHeaderArray: ByteString,
        tokenTxHashProofArray: ByteString,
        tokenSatoshiBytesArray: ByteString,
        inputTokenAddressArray: ByteString,
        inputTokenAmountArray: ByteString,
        nOutputs: bigint,
        tokenOutputIndexArray: ByteString,
        tokenOutputSatoshis: bigint,
        otherOutputArray: ByteString
    ) {
        // check prevouts
        assert(hash256(prevouts) == SigHash.hashPrevouts(txPreimage))
        const thisScript = SigHash.scriptCode(txPreimage)
        const thisScriptLen = len(thisScript)

        // verify tokenScript
        const tokenScriptLen = len(tokenScript)
        const tokenID = TokenProto.getTokenID(tokenScript, tokenScriptLen)
        assert(
            slice(
                thisScript,
                thisScriptLen - AmountCheckProto.TOKEN_ID_OFFSET,
                thisScriptLen -
                    AmountCheckProto.TOKEN_ID_OFFSET +
                    ProtoHeader.UNIQUE_ID_LEN
            ) == tokenID
        )
        const tokenScriptCode = TokenProto.getScriptCode(
            tokenScript,
            tokenScriptLen
        )
        assert(
            slice(
                thisScript,
                thisScriptLen - AmountCheckProto.TOKEN_CODE_HASH_OFFSET,
                thisScriptLen - AmountCheckProto.TOKEN_ID_OFFSET
            ) == hash160(tokenScriptCode)
        )
        assert(TokenProto.checkDataLen(tokenScript, tokenScriptLen))

        // get receiver data
        const nReceivers = Utils.fromLEUnsigned(
            slice(
                thisScript,
                thisScriptLen - AmountCheckProto.NRECERIVERS_OFFSET,
                thisScriptLen - AmountCheckProto.TOKEN_CODE_HASH_OFFSET
            )
        )
        assert(nReceivers >= 0n)

        const addressLen = nReceivers * ProtoHeader.ADDRESS_LEN
        let pos =
            thisScriptLen - AmountCheckProto.NRECERIVERS_OFFSET - addressLen
        const receiverArray = slice(thisScript, pos, pos + addressLen)

        const amountLen = nReceivers * ProtoHeader.AMOUNT_LEN
        pos -= amountLen
        const receiverTokenAmountArray = slice(thisScript, pos, pos + amountLen)
        const nSenders = Utils.fromLEUnsigned(slice(thisScript, pos - 4n, pos))
        pos -= 4n

        const inputTokenIndexArray = slice(thisScript, pos - 4n * nSenders, pos)

        // check token inputs
        let isBurn = true
        let hasBurningAddress = false
        let sumInputToken = 0n
        assert(nSenders <= TokenUnlockContractCheck20To5.MAX_INPUT)
        // max support loop num input token
        let prevIndex = -1n
        let hashProofPos = 0n
        for (let i = 0; i < TokenUnlockContractCheck20To5.MAX_INPUT; i++) {
            if (i < nSenders) {
                const inputIndex = Utils.fromLEUnsigned(
                    slice(
                        inputTokenIndexArray,
                        BigInt(i * 4),
                        BigInt((i + 1) * 4)
                    )
                )
                assert(prevIndex < inputIndex)
                prevIndex = inputIndex
                const tokenOutpoint = slice(
                    prevouts,
                    inputIndex * 36n,
                    (inputIndex + 1n) * 36n
                )
                const tokenTxHeader = slice(
                    tokenTxHeaderArray,
                    BigInt(i) * TxUtil.TX_HEADER_LEN,
                    (BigInt(i) + 1n) * TxUtil.TX_HEADER_LEN
                )

                const address = slice(
                    inputTokenAddressArray,
                    BigInt(i) * 20n,
                    (BigInt(i) + 1n) * 20n
                )
                // input token address should all be burning address or not
                if (address != TokenProto.BURN_ADDRESS) {
                    isBurn = false
                } else {
                    hasBurningAddress = true
                }

                // get new token input script data
                const amount = Utils.fromLEUnsigned(
                    slice(
                        inputTokenAmountArray,
                        BigInt(i) * 8n,
                        (BigInt(i) + 1n) * 8n
                    )
                )
                const newTokenScript = TokenProto.getNewTokenScript(
                    tokenScript,
                    tokenScriptLen,
                    address,
                    amount
                )

                const hashProofLen = Utils.fromLEUnsigned(
                    slice(
                        tokenTxHashProofArray,
                        hashProofPos,
                        hashProofPos + 4n
                    )
                )
                const hashProof = slice(
                    tokenTxHashProofArray,
                    hashProofPos + 4n,
                    hashProofPos + 4n + hashProofLen
                )
                hashProofPos += 4n + hashProofLen
                // verify token inputs's script code
                const satoshiBytes = slice(
                    tokenSatoshiBytesArray,
                    BigInt(i * 8),
                    BigInt((i + 1) * 8)
                )
                const scriptHash = sha256(newTokenScript)
                const proof: TxOutputProof = {
                    txHeader: tokenTxHeader,
                    hashProof: hashProof,
                    satoshiBytes: satoshiBytes,
                    scriptHash: scriptHash,
                }
                TxUtil.verifyTxOutput(proof, tokenOutpoint)

                sumInputToken = sumInputToken + amount
            }
        }

        // check the outputs
        let outputs = toByteString('')
        let sumOutputToken = 0n
        let tokenIndex = 0n
        let otherOutputIndex = 0n
        let tokenOutIndex = nOutputs + 1n
        if (nReceivers > 0n) {
            tokenOutIndex = Utils.fromLEUnsigned(
                slice(tokenOutputIndexArray, 0n, 4n)
            )
        }
        let prevTokenOutIndex = -1n
        assert(nOutputs <= TokenUnlockContractCheck20To5.MAX_OUTPUT)
        for (let i = 0; i < TokenUnlockContractCheck20To5.MAX_OUTPUT; i++) {
            if (BigInt(i) < nOutputs) {
                if (BigInt(i) == tokenOutIndex) {
                    assert(prevTokenOutIndex < tokenOutIndex)
                    const address = slice(
                        receiverArray,
                        tokenIndex * ProtoHeader.ADDRESS_LEN,
                        (tokenIndex + 1n) * ProtoHeader.ADDRESS_LEN
                    )
                    const tokenAmount = Utils.fromLEUnsigned(
                        slice(
                            receiverTokenAmountArray,
                            tokenIndex * ProtoHeader.AMOUNT_LEN,
                            (tokenIndex + 1n) * ProtoHeader.AMOUNT_LEN
                        )
                    )
                    assert(tokenAmount > 0n)
                    sumOutputToken += tokenAmount
                    const outputScript = TokenProto.getNewTokenScript(
                        tokenScript,
                        tokenScriptLen,
                        address,
                        tokenAmount
                    )
                    const output = Utils.buildOutput(
                        outputScript,
                        tokenOutputSatoshis
                    )
                    outputs += output
                    tokenIndex += 1n
                    if (tokenIndex < nReceivers) {
                        prevTokenOutIndex = tokenOutIndex
                        tokenOutIndex = Utils.fromLEUnsigned(
                            slice(
                                tokenOutputIndexArray,
                                tokenIndex * 4n,
                                (tokenIndex + 1n) * 4n
                            )
                        )
                    }
                } else {
                    const outputLen = Utils.fromLEUnsigned(
                        slice(
                            otherOutputArray,
                            otherOutputIndex,
                            otherOutputIndex + 4n
                        )
                    )
                    const output = slice(
                        otherOutputArray,
                        otherOutputIndex + 4n,
                        otherOutputIndex + 4n + outputLen
                    )

                    this.verifyOutput(output, tokenScriptLen, tokenID)

                    outputs += output
                    otherOutputIndex += 4n + outputLen
                }
            }
        }

        if (isBurn) {
            assert(sumOutputToken == 0n)
        } else {
            assert(hasBurningAddress == false)
            assert(sumInputToken == sumOutputToken)
        }

        const hashOutputs = hash256(outputs)
        assert(hashOutputs == SigHash.hashOutputs(txPreimage))

        // check preimage ocs
        assert(
            Tx.checkPreimageSigHashTypeOCS(txPreimage, ProtoHeader.SIG_HASH_ALL)
        )
    }
}

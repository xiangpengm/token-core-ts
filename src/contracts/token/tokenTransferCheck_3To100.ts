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
    Ripemd160,
    slice,
    SigHash,
    toByteString,
    Tx,
    SigHashPreimage,
} from 'scrypt-ts'
import { TxOutputProof, TxUtil } from '../txUtil'
import { ProtoHeader } from '../protoheader'
import { TokenProto } from './tokenProto'
import { AmountCheckProto } from './tokenAmountCheckProto'

export class TokenTransferCheck3To100 extends SmartContract {
    @prop()
    static readonly MAX_INPUT: bigint = 3n
    @prop()
    static readonly MAX_OUTPUT: bigint = 100n

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
        tokenOutputSatoshis: bigint,
        changeSatoshis: bigint,
        changeAddress: Ripemd160,
        opReturnScript: ByteString
    ) {
        // check prevouts
        assert(hash256(prevouts) == SigHash.hashPrevouts(txPreimage))
        const thisScript = SigHash.scriptCode(txPreimage)
        const thisScriptLen = len(thisScript)

        // verify tokenScript
        const tokenScriptLen = len(tokenScript)
        assert(
            slice(
                thisScript,
                thisScriptLen - AmountCheckProto.TOKEN_ID_OFFSET,
                thisScriptLen -
                    AmountCheckProto.TOKEN_ID_OFFSET +
                    ProtoHeader.UNIQUE_ID_LEN
            ) == TokenProto.getTokenID(tokenScript, tokenScriptLen)
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
        assert(nReceivers > 0)
        const addressLen = nReceivers * ProtoHeader.ADDRESS_LEN
        let pos =
            thisScriptLen - AmountCheckProto.NRECERIVERS_OFFSET - addressLen
        const receiverArray = slice(thisScript, pos, pos + addressLen)

        const amountLen = nReceivers * ProtoHeader.AMOUNT_LEN
        pos -= amountLen
        const receiverTokenAmountArray = slice(thisScript, pos, pos + amountLen)
        const nSenders = Utils.fromLEUnsigned(slice(thisScript, pos - 4n, pos))

        // check token inputs
        let sumInputToken = 0n
        let hashProofPos = 0n
        assert(nSenders <= TokenTransferCheck3To100.MAX_INPUT)
        // max support loop num input token
        for (let i = 0; i < TokenTransferCheck3To100.MAX_INPUT; i++) {
            if (i < nSenders) {
                const tokenOutpoint = slice(
                    prevouts,
                    BigInt(i * 36),
                    BigInt((i + 1) * 36)
                )
                const tokenTxHeader = slice(
                    tokenTxHeaderArray,
                    BigInt(i) * TxUtil.TX_HEADER_LEN,
                    (BigInt(i) + 1n) * TxUtil.TX_HEADER_LEN
                )
                // get new token input script data
                const address = slice(
                    inputTokenAddressArray,
                    BigInt(i * 20),
                    BigInt((i + 1) * 20)
                )
                const amount = Utils.fromLEUnsigned(
                    slice(
                        inputTokenAmountArray,
                        BigInt(i * 8),
                        BigInt((i + 1) * 8)
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
        // max support loop num receiver, you can change this num, but will cause the contrac size increase. you can customize your output
        let sumOutputToken = 0n
        assert(nReceivers <= TokenTransferCheck3To100.MAX_OUTPUT)
        for (let i = 0; i < TokenTransferCheck3To100.MAX_OUTPUT; i++) {
            if (i < nReceivers) {
                const address = slice(
                    receiverArray,
                    BigInt(i) * ProtoHeader.ADDRESS_LEN,
                    BigInt(i + 1) * ProtoHeader.ADDRESS_LEN
                )
                const tokenAmount = Utils.fromLEUnsigned(
                    slice(
                        receiverTokenAmountArray,
                        BigInt(i) * ProtoHeader.AMOUNT_LEN,
                        BigInt(i + 1) * ProtoHeader.AMOUNT_LEN
                    )
                )
                assert(tokenAmount > 0n)
                sumOutputToken = sumOutputToken + tokenAmount
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
                outputs = outputs + output
            }
        }
        assert(sumInputToken == sumOutputToken)

        // op_false op_return output
        // optional
        if (len(opReturnScript) > 0) {
            assert(slice(opReturnScript, 0n, 2n) == toByteString('006a'))
            const opReturnOutput = Utils.buildOutput(opReturnScript, 0n)
            outputs = outputs + opReturnOutput
        }

        // mvc change output
        const changeOutput = TxUtil.genMvcOutput(changeSatoshis, changeAddress)
        outputs = outputs + changeOutput

        const hashOutputs = hash256(outputs)
        assert(hashOutputs == SigHash.hashOutputs(txPreimage))

        // check preimage ocs
        assert(
            Tx.checkPreimageSigHashTypeOCS(txPreimage, ProtoHeader.SIG_HASH_ALL)
        )
    }
}

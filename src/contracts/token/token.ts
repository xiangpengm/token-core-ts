import {
    method,
    assert,
    SmartContract,
    ByteString,
    prop,
    PubKey,
    Sig,
    FixedArray,
    Utils,
    len,
    sha256,
    hash256,
    hash160,
    ripemd160,
    SigHashPreimage,
    slice,
    SigHash,
} from 'scrypt-ts'
import { TxInputProof, TxOutputProof, TxUtil } from '../txUtil'
import { ProtoHeader } from '../protoheader'
import { TokenProto } from './tokenProto'
import { Backtrace } from '../backtrace'
import { AmountCheckProto } from './tokenAmountCheckProto'

/**
 * Token contract
 * @contructor
 * @param transferAmountCheckCodeHashArray {} script code hash array (not including data part) of contracts which are used to check token amounts between tx's inputs and outputs when transfering tokens.
 * @param unlockAmountCheckCodeHashArray {} script code hash array (not including data part) of contracts which are used to check token amounts between tx's inputs and outputs when unlock tokens from contracts.
 */
export class Token extends SmartContract {
    @prop()
    transferAmountCheckCodeHashArray: FixedArray<ByteString, 5>

    @prop()
    unlockAmountCheckCodeHashArray: FixedArray<ByteString, 5>

    constructor(
        transferAmountCheckCodeHashArray: FixedArray<ByteString, 5>,
        unlockAmountCheckCodeHashArray: FixedArray<ByteString, 5>
    ) {
        super(...arguments)
        this.transferAmountCheckCodeHashArray = transferAmountCheckCodeHashArray
        this.unlockAmountCheckCodeHashArray = unlockAmountCheckCodeHashArray
    }

    /**
     * @function unlock
     * @param txPreimage {SigHashPreimage} preimage of tx.
     * @param prevouts {bytes} previous outputs.
     * @param tokenInputIndex {int} the i-st token input in this tx
     * @param amountCheckHashIndex {int} the index number of the amountCheck contract this tx used
     * @param amountCheckInputIndex {int} the input index of amountCheck contract in this tx
     * @param amountCheckTxProof {TxOutputProof} the amountCheck utxo output proof in amountCheckTx
     * @param amountCheckScriptData {int} the data part of amountCheck locking script
     * @param prevTokenInputIndex {int} the input index of prev token utxo in tokenTx
     * @param prevTokenAddress {bytes} the token address of prev token utxo
     * @param prevTokenAmount {int} the token amount of prev token utxo
     * @param tokenTxOutputProof {TxOutputProof} the token utxo output proof in tokenTx
     * @param prevTokenTxProof {TxOutputProof} the prev token utxo output proof in prevTokenTx
     * @param senderPubKey {} the pubkey of owner, only transfer need
     * @param senderSig {} the signature of owner, only transfer need
     * @param contractInputIndex {int} the input index of contract which control token utxo, only unlockFromContract need
     * @param contractTxProof {} the contract utxo output proof in contractTx
     * @param operation {int} 1: transfer, 2: unlock from contract
     */
    @method()
    public unlock(
        txPreimage: SigHashPreimage,
        prevouts: ByteString,
        // amountCheck
        tokenInputIndex: bigint,
        amountCheckHashIndex: bigint,
        amountCheckInputIndex: bigint,
        amountCheckTxProof: TxOutputProof,
        amountCheckScript: ByteString,
        // token
        prevTokenInputIndex: bigint,
        prevTokenAddress: ByteString,
        prevTokenAmount: bigint,
        tokenTxHeader: ByteString,
        tokenTxInputProof: TxInputProof,
        prevTokenTxProof: TxOutputProof,
        // sig data
        senderPubKey: PubKey,
        senderSig: Sig,
        // contract
        contractInputIndex: bigint,
        contractTxProof: TxOutputProof,
        // op
        operation: bigint
    ) {
        // verify this tx's version
        assert(
            Utils.fromLEUnsigned(SigHash.nVersion(txPreimage)) ==
                ProtoHeader.TX_VERSION
        )
        assert(hash256(prevouts) == SigHash.hashPrevouts(txPreimage))

        const tokenScript = SigHash.scriptCode(txPreimage)
        const tokenScriptLen = len(tokenScript)

        if (operation == TokenProto.OP_TRANSFER) {
            const senderAddress = TokenProto.getTokenAddress(
                tokenScript,
                tokenScriptLen
            )

            // burning address is not allowed to unlock token from sig
            assert(senderAddress != TokenProto.BURN_ADDRESS)

            // authorize
            assert(hash160(senderPubKey) == senderAddress)
            assert(this.checkSig(senderSig, senderPubKey))
        } else if (operation == TokenProto.OP_UNLOCK_FROM_CONTRACT) {
            // verify the lockContractTx
            const contractHash = TokenProto.getTokenAddress(
                tokenScript,
                tokenScriptLen
            )
            // do not check burning address
            if (contractHash != TokenProto.BURN_ADDRESS) {
                assert(contractHash == ripemd160(contractTxProof.scriptHash))
                // verify the contract locking script
                const contractOutpoint = slice(
                    prevouts,
                    contractInputIndex * TxUtil.OUTPOINT_LEN,
                    (contractInputIndex + 1n) * TxUtil.OUTPOINT_LEN
                )
                TxUtil.verifyTxOutput(contractTxProof, contractOutpoint)
            }
        } else {
            // do not remove
            assert(false)
        }

        // backtrace verify
        // backtrace to genesis
        const genesisTxid = TokenProto.getGenesisTxid(
            tokenScript,
            tokenScriptLen
        )

        if (
            genesisTxid !=
            hash256(prevTokenTxProof.txHeader) +
                tokenTxInputProof.outputIndexBytes
        ) {
            // backtrace to genesis contract
            const genesisHash = TokenProto.getGenesisHash(
                tokenScript,
                tokenScriptLen
            )
            const backtraceGenesis =
                genesisHash == ripemd160(prevTokenTxProof.scriptHash)

            // backtrace to token contract
            // verify prev token script data and script code
            const prevTokenScript = TokenProto.getNewTokenScript(
                tokenScript,
                tokenScriptLen,
                prevTokenAddress,
                prevTokenAmount
            )
            const backtraceToken =
                sha256(prevTokenScript) == prevTokenTxProof.scriptHash

            assert(backtraceGenesis || backtraceToken)
        }

        // verify tx and prevTx script
        const thisOutpoint = SigHash.outpoint(txPreimage)
        Backtrace.verify(
            thisOutpoint,
            tokenTxHeader,
            prevTokenInputIndex,
            prevTokenTxProof,
            genesisTxid,
            tokenTxInputProof
        )

        // verify amountCheck contract
        const tokenID = TokenProto.getTokenID(tokenScript, tokenScriptLen)
        // TODO: remove tokenCodeHash checking and use checkPreimageOCS
        const tokenCodeHash = TokenProto.getScriptCodeHash(
            tokenScript,
            tokenScriptLen
        )

        this.verifyAmountCheckContract(
            prevouts,
            amountCheckHashIndex,
            amountCheckInputIndex,
            amountCheckTxProof,
            amountCheckScript,
            tokenID,
            tokenCodeHash,
            thisOutpoint,
            tokenInputIndex,
            operation
        )
        assert(
            this.checkPreimageSigHashType(txPreimage, ProtoHeader.SIG_HASH_ALL)
        )
    }

    @method()
    verifyAmountCheckContract(
        prevouts: ByteString,
        amountCheckHashIndex: bigint,
        amountCheckInputIndex: bigint,
        amountCheckTxProof: TxOutputProof,
        amountCheckScript: ByteString,
        tokenID: ByteString,
        tokenCodeHash: ByteString,
        thisOutpoint: ByteString,
        tokenInputIndex: bigint,
        operation: bigint
    ): boolean {
        const amountCheckOutpoint = slice(
            prevouts,
            amountCheckInputIndex * TxUtil.OUTPOINT_LEN,
            (amountCheckInputIndex + 1n) * TxUtil.OUTPOINT_LEN
        )

        // verify amountCheckData belong amountCheckScript
        assert(sha256(amountCheckScript) == amountCheckTxProof.scriptHash)
        TxUtil.verifyTxOutput(amountCheckTxProof, amountCheckOutpoint)

        // verify tokenInput

        // check tokenID and tokenCodeHash
        const amountCheckScriptLen = len(amountCheckScript)
        assert(
            tokenID ==
                slice(
                    amountCheckScript,
                    amountCheckScriptLen - AmountCheckProto.TOKEN_ID_OFFSET,
                    amountCheckScriptLen -
                        AmountCheckProto.TOKEN_ID_OFFSET +
                        ProtoHeader.UNIQUE_ID_LEN
                )
        )
        assert(
            tokenCodeHash ==
                slice(
                    amountCheckScript,
                    amountCheckScriptLen -
                        AmountCheckProto.TOKEN_CODE_HASH_OFFSET,
                    amountCheckScriptLen - AmountCheckProto.TOKEN_ID_OFFSET
                )
        )

        // get token output number
        const nReceivers = Utils.fromLEUnsigned(
            slice(
                amountCheckScript,
                amountCheckScriptLen - AmountCheckProto.NRECERIVERS_OFFSET,
                amountCheckScriptLen - AmountCheckProto.TOKEN_CODE_HASH_OFFSET
            )
        )

        let pos =
            AmountCheckProto.NRECERIVERS_OFFSET +
            nReceivers * (ProtoHeader.ADDRESS_LEN + ProtoHeader.AMOUNT_LEN) +
            4n
        // get token input number
        const nSenders = Utils.fromLEUnsigned(
            slice(
                amountCheckScript,
                amountCheckScriptLen - pos,
                amountCheckScriptLen - pos + 4n
            )
        )

        // check if this token input is verified by amountCheck contract
        // tokenInputIndex should be included in amountCheck's tokenInputArray
        if (operation == TokenProto.OP_UNLOCK_FROM_CONTRACT) {
            assert(nReceivers >= 0)
            const inputIndexArray = slice(
                amountCheckScript,
                amountCheckScriptLen - pos - nSenders * 4n,
                amountCheckScriptLen - pos
            )
            pos += nSenders * 4n
            tokenInputIndex = Utils.fromLEUnsigned(
                slice(
                    inputIndexArray,
                    tokenInputIndex * 4n,
                    (tokenInputIndex + 1n) * 4n
                )
            )
        } else {
            assert(nReceivers > 0)
            assert(tokenInputIndex < nSenders)
        }

        // code hash do not count data length + data
        const dataOffset = TxUtil.getVarOpLen(pos) + pos

        const hash = hash160(
            slice(amountCheckScript, 0n, amountCheckScriptLen - dataOffset)
        )
        assert(
            hash ==
                this.transferAmountCheckCodeHashArray[
                    Number(amountCheckHashIndex)
                ] ||
                hash ==
                    this.unlockAmountCheckCodeHashArray[
                        Number(amountCheckHashIndex)
                    ]
        )

        // verify tokenInputIndex
        assert(
            thisOutpoint ==
                slice(
                    prevouts,
                    tokenInputIndex * 36n,
                    (tokenInputIndex + 1n) * 36n
                )
        )
        return true
    }
}

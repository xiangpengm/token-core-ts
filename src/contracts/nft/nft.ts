import {
    method,
    PubKey,
    SmartContract,
    Sig,
    ByteString,
    Ripemd160,
    Utils,
    hash160,
    sha256,
    assert,
    SigHash,
    len,
    slice,
    toByteString,
    hash256,
    SigHashPreimage,
    prop,
    ripemd160,
    FixedArray,
} from 'scrypt-ts'
import { TxInputProof, TxOutputProof, TxUtil } from '../txUtil'
import { ProtoHeader } from '../protoheader'
import { Backtrace } from '../backtrace'
import { NftProto } from './nftProto'
import { NftAmountCheckProto } from './nftAmountCheckProto'

export class Nft extends SmartContract {
    @prop()
    unlockContractCodeHashArray: FixedArray<ByteString, 5>

    constructor(unlockContractCodeHashArray: FixedArray<ByteString, 5>) {
        super(...arguments)
        this.unlockContractCodeHashArray = unlockContractCodeHashArray
    }

    /**
     * @function unlock
     * @param txPreimage {SigHashPreimage} preimage
     * @param prevouts {bytes} previous outputs
     * @param prevNftAddress {bytes} the owner address of previous nft contract
     * @param genesisScript {bytes} the nft genesis locking script, only needed when use a new generated nft for the first time
     * @param senderPubKey {PubKey} the owner's pubkey, only transfer need
     * @param senderSig {Sig} the sig of owner private key, only transfer need
     * @param receiverAddress {bytes} the receiverAddress, only transfer need
     * @param nftOutputSatoshis {int} the nft output contract satoshis, only transfer need
     * @param opReturnScript {bytes} op_false op_return script, optional, only transfer need
     * @param changeAddress {Ripemd160} change mvc address, only transfer need
     * @param checkInputIndex {int} nftUnlockContractCheck contract input index, only unlockFromContract need
     * @param checkScriptTx {bytes} nftUnlockContractCheck contract raw tx, only unlockFromContract need
     * @param lockContractInputIndex {int} lock contract input index, only unlockFromContract need
     * @param lockContractTx {bytes} lock contract raw tx, only unlockFromContract need
     * @param opration {int} 1 transfer, 2 unlockFromContract
     */
    @method()
    public unlock(
        txPreimage: SigHashPreimage,
        prevouts: ByteString,
        // nft
        prevNftInputIndex: bigint,
        prevNftAddress: ByteString,
        nftTxHeader: ByteString,
        nftTxInputProof: TxInputProof,
        prevNftTxProof: TxOutputProof,
        genesisScript: ByteString,
        // contract
        contractInputIndex: bigint,
        contractTxProof: TxOutputProof,
        // unlockCheck
        amountCheckHashIndex: bigint,
        amountCheckInputIndex: bigint,
        amountCheckTxProof: TxOutputProof,
        amountCheckScript: ByteString,
        // sig
        senderPubKey: PubKey,
        senderSig: Sig,
        // output
        receiverAddress: ByteString,
        nftOutputSatoshis: bigint,
        opReturnScript: ByteString,
        changeAddress: Ripemd160,
        changeSatoshis: bigint,
        operation: bigint
    ) {
        // verify this tx's version
        assert(
            Utils.fromLEUnsigned(SigHash.nVersion(txPreimage)) ==
                ProtoHeader.TX_VERSION
        )

        assert(hash256(prevouts) == SigHash.hashPrevouts(txPreimage))

        // get nftScript
        const nftScript = SigHash.scriptCode(txPreimage)
        const nftScriptLen = len(nftScript)
        const nftScriptCodeSha256 = sha256(
            NftProto.getScriptCode(nftScript, nftScriptLen)
        )
        assert(
            NftProto.getTokenIndex(nftScript, nftScriptLen) <
                NftProto.getTotalSupply(nftScript, nftScriptLen)
        )

        // backtrace
        const sensibleID = NftProto.getGenesisTxid(nftScript, nftScriptLen)
        const thisOutpoint = SigHash.outpoint(txPreimage)
        // verify tx and prevTx script
        Backtrace.verify(
            thisOutpoint,
            nftTxHeader,
            prevNftInputIndex,
            prevNftTxProof,
            sensibleID,
            nftTxInputProof
        )

        if (
            sensibleID !=
            hash256(prevNftTxProof.txHeader) + nftTxInputProof.outputIndexBytes
        ) {
            // backtrace to nft contract
            // verify prev nft script data and script code
            const prevNftScript = NftProto.getNewNftScript(
                nftScript,
                nftScriptLen,
                prevNftAddress
            )
            const backtraceToken =
                sha256(prevNftScript) == prevNftTxProof.scriptHash

            if (!backtraceToken) {
                // genesis
                const genesisScriptLen = len(genesisScript)
                assert(
                    NftProto.getTokenIndex(nftScript, nftScriptLen) ==
                        NftProto.getTokenIndex(genesisScript, genesisScriptLen)
                )
                const newGenesisScript = NftProto.getNewGenesisScript(
                    genesisScript,
                    genesisScriptLen,
                    sensibleID,
                    0n
                )
                // verify genesisScript
                assert(sha256(genesisScript) == prevNftTxProof.scriptHash)
                const genesisHash = NftProto.getGenesisHash(
                    nftScript,
                    nftScriptLen
                )
                assert(hash160(newGenesisScript) == genesisHash)
            }
        }

        if (operation == NftProto.OP_TRANSFER) {
            // check output
            const nftOutputScript = NftProto.getNewNftScript(
                nftScript,
                nftScriptLen,
                receiverAddress
            )
            const nftOutput = Utils.buildOutput(
                nftOutputScript,
                nftOutputSatoshis
            )

            let opReturnOutput = toByteString('')
            if (len(opReturnScript) > 0) {
                assert(slice(opReturnScript, 0n, 2n) == toByteString('006a'))
                opReturnOutput = Utils.buildOutput(opReturnScript, 0n)
            }

            const changeOutput = TxUtil.genMvcOutput(
                changeSatoshis,
                changeAddress
            )

            const outputs = nftOutput + opReturnOutput + changeOutput
            const hashOutputs = hash256(outputs)
            assert(hashOutputs == SigHash.hashOutputs(txPreimage))

            // checkSig
            const senderAddress = NftProto.getNftAddress(
                nftScript,
                nftScriptLen
            )
            assert(senderAddress != NftProto.BURN_ADDRESS)
            assert(hash160(senderPubKey) == senderAddress)
            assert(this.checkSig(senderSig, senderPubKey))
        } else {
            const contractHash = NftProto.getNftAddress(nftScript, nftScriptLen)

            // verify lockContract
            if (contractHash != NftProto.BURN_ADDRESS) {
                assert(contractHash == ripemd160(contractTxProof.scriptHash))
                // verify the contract locking script
                const contractOutpoint = slice(
                    prevouts,
                    contractInputIndex * TxUtil.OUTPOINT_LEN,
                    (contractInputIndex + 1n) * TxUtil.OUTPOINT_LEN
                )
                TxUtil.verifyTxOutput(contractTxProof, contractOutpoint)
            }

            const amountCheckOutpoint = slice(
                prevouts,
                amountCheckInputIndex * TxUtil.OUTPOINT_LEN,
                (amountCheckInputIndex + 1n) * TxUtil.OUTPOINT_LEN
            )
            // verify amountCheckData belong amountCheckScript
            assert(sha256(amountCheckScript) == amountCheckTxProof.scriptHash)
            TxUtil.verifyTxOutput(amountCheckTxProof, amountCheckOutpoint)

            const amountCheckScriptLen = len(amountCheckScript)

            // check sensibleID and nftCodeHash
            const nftID = NftProto.getNftID(nftScript, nftScriptLen)
            assert(
                nftID ==
                    NftAmountCheckProto.getNftID(
                        amountCheckScript,
                        amountCheckScriptLen
                    )
            )

            const nftCodeHash = ripemd160(nftScriptCodeSha256)
            assert(
                nftCodeHash ==
                    NftAmountCheckProto.getNftCodeHash(
                        amountCheckScript,
                        amountCheckScriptLen
                    )
            )

            const hash = hash160(
                slice(
                    amountCheckScript,
                    0n,
                    amountCheckScriptLen - NftAmountCheckProto.DATA_OFFSET
                )
            )
            assert(
                hash ==
                    this.unlockContractCodeHashArray[
                        Number(amountCheckHashIndex)
                    ]
            )
        }

        assert(
            this.checkPreimageSigHashType(txPreimage, ProtoHeader.SIG_HASH_ALL)
        )
    }
}

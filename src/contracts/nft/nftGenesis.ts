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
} from 'scrypt-ts'
import { TxInputProof, TxOutputProof } from '../txUtil'
import { ProtoHeader } from '../protoheader'
import { Backtrace } from '../backtrace'
import { NftProto } from './nftProto'
/**
 * Nft contract
 * @constructor
 */
export class NftGenesis extends SmartContract {
    /**
     * @function unlock
     * @param txPreimage {SigHashPreimage} preimage
     * @param sig {Sig} the sig of issuer private key
     * @param genesisSatoshis {int} the nft genesis contract output satoshis
     * @param nftScript {bytes} the nft contract output script
     * @param nftSatoshis {int} the nft contract output satoshis
     * @param changeAddress {Ripemd160} the mvc change address
     * @param changeSatoshis {int} the mvc change satoshis
     * @param opReturnScript {bytes} the op_false op_return script, optional
     */
    @method()
    public unlock(
        txPreimage: SigHashPreimage,
        // sig
        pubKey: PubKey,
        sig: Sig,
        // genesisTx input proof
        genesisTxHeader: ByteString,
        prevInputIndex: bigint,
        genesisTxInputProof: TxInputProof,
        // prev genesis tx output proof
        prevGenesisTxHeader: ByteString,
        prevTxOutputHashProof: ByteString,
        prevTxOutputSatoshiBytes: ByteString,
        // output
        nftScript: ByteString,
        genesisSatoshis: bigint,
        nftSatoshis: bigint,
        changeAddress: Ripemd160,
        changeSatoshis: bigint,
        opReturnScript: ByteString
    ) {
        // verify this tx's version
        assert(
            Utils.fromLEUnsigned(SigHash.nVersion(txPreimage)) ==
                ProtoHeader.TX_VERSION
        )

        // check input script oracle data
        const genesisScript = SigHash.scriptCode(txPreimage)
        const genesisScriptLen = len(genesisScript)

        let sensibleID = NftProto.getGenesisTxid(
            genesisScript,
            genesisScriptLen
        )
        const totalSupply = NftProto.getTotalSupply(
            genesisScript,
            genesisScriptLen
        )
        const tokenIndex = NftProto.getTokenIndex(
            genesisScript,
            genesisScriptLen
        )
        assert(tokenIndex < totalSupply)

        const thisOutpoint = SigHash.outpoint(txPreimage)
        let isFirst = false
        if (sensibleID == ProtoHeader.NULL_GENESIS_TXID) {
            isFirst = true
            sensibleID = thisOutpoint
        }
        assert(NftProto.checkProtoHeader(genesisScript, genesisScriptLen))
        // check opreturn
        assert(NftProto.checkDataLen(genesisScript, genesisScriptLen))
        assert(NftProto.checkOpReturn(genesisScript, genesisScriptLen))

        if (!isFirst) {
            // backtrace to genesis script
            const prevGenesisScript = NftProto.getNewGenesisScript(
                genesisScript,
                genesisScriptLen,
                sensibleID,
                tokenIndex - 1n
            )
            const prevScriptHash = sha256(prevGenesisScript)
            const prevGenesisTxProof: TxOutputProof = {
                txHeader: prevGenesisTxHeader,
                hashProof: prevTxOutputHashProof,
                satoshiBytes: prevTxOutputSatoshiBytes,
                scriptHash: prevScriptHash,
            }
            Backtrace.verify(
                thisOutpoint,
                genesisTxHeader,
                prevInputIndex,
                prevGenesisTxProof,
                sensibleID,
                genesisTxInputProof
            )
        }

        // check nftScript oracle data
        const nftScriptLen = len(nftScript)

        assert(sensibleID == NftProto.getGenesisTxid(nftScript, nftScriptLen))
        assert(tokenIndex == NftProto.getTokenIndex(nftScript, nftScriptLen))
        assert(totalSupply == NftProto.getTotalSupply(nftScript, nftScriptLen))
        assert(NftProto.checkProtoHeader(nftScript, nftScriptLen))
        // check opreturn
        assert(NftProto.checkDataLen(nftScript, nftScriptLen))
        assert(NftProto.checkOpReturn(nftScript, nftScriptLen))

        //check genesisHash
        const genesisScriptTmp = NftProto.getNewGenesisScript(
            genesisScript,
            genesisScriptLen,
            sensibleID,
            0n
        )
        const genesisHash = hash160(genesisScriptTmp)
        assert(NftProto.getGenesisHash(nftScript, nftScriptLen) == genesisHash)

        let genesisOutput = toByteString('')
        if (tokenIndex != totalSupply - 1n) {
            const newGenesisScript = NftProto.getNewGenesisScript(
                genesisScript,
                len(genesisScript),
                sensibleID,
                tokenIndex + 1n
            )
            genesisOutput = Utils.buildOutput(newGenesisScript, genesisSatoshis)
        }
        const nftOutput = Utils.buildOutput(nftScript, nftSatoshis)

        // op_false op_return output
        let opReturnOutput = toByteString('')
        if (len(opReturnScript) > 0) {
            assert(slice(opReturnScript, 0n, 2n) == toByteString('006a'))
            opReturnOutput = Utils.buildOutput(opReturnScript, 0n)
        }

        let changeOutput = toByteString('')
        if (changeSatoshis > 0) {
            const changeScript = Utils.buildPublicKeyHashScript(changeAddress)
            changeOutput = Utils.buildOutput(changeScript, changeSatoshis)
        }
        const hashOutput = hash256(
            genesisOutput + nftOutput + opReturnOutput + changeOutput
        )
        assert(hashOutput == SigHash.hashOutputs(txPreimage))

        // check sig
        const senderAddress = NftProto.getNftAddress(
            genesisScript,
            genesisScriptLen
        )
        assert(senderAddress == hash160(pubKey))
        assert(this.checkSig(sig, pubKey))

        assert(
            this.checkPreimageSigHashType(txPreimage, ProtoHeader.SIG_HASH_ALL)
        )
    }
}

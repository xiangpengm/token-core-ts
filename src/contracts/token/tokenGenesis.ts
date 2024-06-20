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
import { TxInputProof, TxOutputProof, TxUtil } from '../txUtil'
import { ProtoHeader } from '../protoheader'
import { TokenProto } from './tokenProto'
import { Backtrace } from '../backtrace'

export class TokenGenesis extends SmartContract {
    @method()
    public unlock(
        txPreimage: SigHashPreimage,
        pubKey: PubKey,
        sig: Sig,
        tokenScript: ByteString,
        // genesisTx input proof
        genesisTxHeader: ByteString,
        prevInputIndex: bigint,
        genesisTxInputProof: TxInputProof,
        // prev genesis tx output proof
        prevGenesisTxHeader: ByteString,
        prevTxOutputHashProof: ByteString,
        prevTxOutputSatoshiBytes: ByteString,
        // output
        genesisSatoshis: bigint,
        tokenSatoshis: bigint,
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

        const tokenValue = TokenProto.getTokenAmount(
            genesisScript,
            genesisScriptLen
        )
        assert(tokenValue == 0n)
        assert(
            TokenProto.getGenesisHash(genesisScript, genesisScriptLen) ==
                toByteString('0000000000000000000000000000000000000000')
        )
        let genesisTxid = TokenProto.getGenesisTxid(
            genesisScript,
            genesisScriptLen
        )
        let isFirst = false
        const thisOutpoint = SigHash.outpoint(txPreimage)
        if (
            genesisTxid ==
            toByteString(
                '000000000000000000000000000000000000000000000000000000000000000000000000'
            )
        ) {
            isFirst = true
            genesisTxid = thisOutpoint
        }
        assert(TokenProto.checkProtoHeader(genesisScript, genesisScriptLen))
        // check opreturn
        assert(TokenProto.checkDataLen(genesisScript, genesisScriptLen))

        if (!isFirst) {
            // backtrace to genesis script
            const prevScriptHash = sha256(genesisScript)
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
                genesisTxid,
                genesisTxInputProof
            )
        }

        // genesisHash
        const newGenesisScript = TokenProto.getNewGenesisScript(
            genesisScript,
            genesisScriptLen,
            genesisTxid
        )
        const genesisHash = hash160(newGenesisScript)

        // check tokenScript data
        const tokenScriptLen = len(tokenScript)

        assert(
            genesisTxid ==
                TokenProto.getGenesisTxid(tokenScript, tokenScriptLen)
        )
        assert(
            genesisHash ==
                TokenProto.getGenesisHash(tokenScript, tokenScriptLen)
        )
        assert(
            TokenProto.getTokenMetaData(genesisScript, genesisScriptLen) ==
                TokenProto.getTokenMetaData(tokenScript, tokenScriptLen)
        )
        // check data part
        assert(TokenProto.checkDataLen(tokenScript, tokenScriptLen))

        let genesisOutput = toByteString('')
        if (genesisSatoshis > 0n) {
            genesisOutput = Utils.buildOutput(newGenesisScript, genesisSatoshis)
        }
        const tokenOutput = Utils.buildOutput(tokenScript, tokenSatoshis)

        // op_false op_return output
        let opReturnOutput = toByteString('')
        if (len(opReturnScript) > 0) {
            assert(slice(opReturnScript, 0n, 2n) == toByteString('006a'))
            opReturnOutput = Utils.buildOutput(opReturnScript, 0n)
        }

        // mvc change output
        const changeOutput = TxUtil.genMvcOutput(changeSatoshis, changeAddress)

        const hashOutput = hash256(
            genesisOutput + tokenOutput + opReturnOutput + changeOutput
        )
        assert(hashOutput == SigHash.hashOutputs(txPreimage))

        // check sig
        const senderAddress = TokenProto.getTokenAddress(
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

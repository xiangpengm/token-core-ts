import {
    assert,
    method,
    prop,
    hash256,
    Ripemd160,
    SmartContract,
    Utils,
    SigHash,
    SigHashPreimage,
    ByteString,
    toByteString,
    PubKey,
    hash160,
    sha256,
    len,
    Tx,
    Sig,
    slice,
} from 'scrypt-ts'
import { ProtoHeader } from '../protoheader'
import { NftProto } from './nftProto'
import { TxOutputProof, TxUtil } from '../txUtil'
import { TokenProto } from '../token/tokenProto'

export class TokenBuyForNft extends SmartContract {
    static readonly nftInputIndex: bigint = 2n

    static readonly OP_SELL: bigint = 1n
    static readonly OP_REFUND_TOKEN: bigint = 2n

    @prop()
    senderAddress: Ripemd160

    @prop()
    mvcRecAmount: bigint

    @prop()
    nftCodeHash: ByteString

    @prop()
    nftID: ByteString

    constructor(
        senderAddress: Ripemd160,
        mvcRecAmount: bigint,
        nftCodeHash: ByteString,
        nftID: ByteString
    ) {
        super(...arguments)
        this.senderAddress = senderAddress
        this.mvcRecAmount = mvcRecAmount
        this.nftCodeHash = nftCodeHash
        this.nftID = nftID
    }

    @method()
    public unlock(
        txPreimage: SigHashPreimage,
        prevouts: ByteString,
        // nft
        nftScript: ByteString,
        nftTxHeader: ByteString,
        nftTxHashProof: ByteString,
        nftTxSatoshiBytes: ByteString,
        // token
        tokenScript: ByteString,
        // sig
        senderPubKey: PubKey,
        senderSig: Sig,
        // output
        tokenOutputSatoshis: bigint,
        nftOutputSatoshis: bigint,
        op: bigint
    ) {
        // check prevouts
        assert(hash256(prevouts) == SigHash.hashPrevouts(txPreimage))

        let outputs = toByteString('')
        if (op == TokenBuyForNft.OP_SELL) {
            // check token input
            const nftOutpoint = slice(
                prevouts,
                TokenBuyForNft.nftInputIndex * TxUtil.OUTPOINT_LEN,
                (TokenBuyForNft.nftInputIndex + 1n) * TxUtil.OUTPOINT_LEN
            )
            const nftScriptLen = len(nftScript)
            const nftProof: TxOutputProof = {
                txHeader: nftTxHeader,
                hashProof: nftTxHashProof,
                satoshiBytes: nftTxSatoshiBytes,
                scriptHash: sha256(nftScript),
            }
            TxUtil.verifyTxOutput(nftProof, nftOutpoint)

            assert(
                this.nftCodeHash ==
                    NftProto.getScriptCodeHash(nftScript, nftScriptLen)
            )
            assert(this.nftID == NftProto.getNftID(nftScript, nftScriptLen))

            // token
            const newNftScript = NftProto.getNewNftScript(
                nftScript,
                nftScriptLen,
                this.senderAddress
            )
            outputs = Utils.buildOutput(newNftScript, nftOutputSatoshis)
        } else {
            // do not check token id and codeHash

            // check output token address
            assert(
                TokenProto.getTokenAddress(tokenScript, len(tokenScript)) ==
                    this.senderAddress
            )
            outputs = Utils.buildOutput(tokenScript, tokenOutputSatoshis)

            // check sig
            assert(hash160(senderPubKey) == this.senderAddress)
            assert(this.checkSig(senderSig, senderPubKey))
        }
        assert(hash256(outputs) == SigHash.hashOutputs(txPreimage))
        assert(
            Tx.checkPreimageSigHashTypeOCS(
                txPreimage,
                ProtoHeader.SIG_HASH_SINGLE
            )
        )
    }
}

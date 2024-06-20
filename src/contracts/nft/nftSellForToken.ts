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

export class NftSellForToken extends SmartContract {
    @prop()
    senderAddress: Ripemd160

    @prop()
    tokenAmount: bigint

    @prop()
    tokenID: ByteString

    @prop()
    tokenCodeHash: ByteString

    static readonly tokenInputIndex = 3n
    static readonly OP_SELL = 1n
    static readonly OP_REFUND_NFT = 2n

    constructor(
        senderAddress: Ripemd160,
        tokenAmount: bigint,
        tokenID: ByteString,
        tokenCodeHash: ByteString
    ) {
        super(...arguments)
        this.senderAddress = senderAddress
        this.tokenAmount = tokenAmount
        this.tokenID = tokenID
        this.tokenCodeHash = tokenCodeHash
    }

    @method()
    public unlock(
        txPreimage: SigHashPreimage,
        prevouts: ByteString,
        // token
        tokenScript: ByteString,
        tokenTxHeader: ByteString,
        tokenTxHashProof: ByteString,
        tokenTxSatoshiBytes: ByteString,
        // nft
        nftScript: ByteString,
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
        if (op == NftSellForToken.OP_SELL) {
            // check token input
            const tokenOutpoint = slice(
                prevouts,
                NftSellForToken.tokenInputIndex * TxUtil.OUTPOINT_LEN,
                (NftSellForToken.tokenInputIndex + 1n) * TxUtil.OUTPOINT_LEN
            )
            const tokenScriptLen = len(tokenScript)
            const tokenProof: TxOutputProof = {
                txHeader: tokenTxHeader,
                hashProof: tokenTxHashProof,
                satoshiBytes: tokenTxSatoshiBytes,
                scriptHash: sha256(tokenScript),
            }
            TxUtil.verifyTxOutput(tokenProof, tokenOutpoint)

            assert(
                this.tokenID ==
                    TokenProto.getTokenID(tokenScript, tokenScriptLen)
            )
            assert(
                this.tokenCodeHash ==
                    TokenProto.getScriptCodeHash(tokenScript, tokenScriptLen)
            )

            // token
            const newTokenScript = TokenProto.getNewTokenScript(
                tokenScript,
                tokenScriptLen,
                this.senderAddress,
                this.tokenAmount
            )
            outputs = Utils.buildOutput(newTokenScript, tokenOutputSatoshis)
        } else {
            // do not check nft id and codeHash to refund all kinds nft
            const outputScript = NftProto.getNewNftScript(
                nftScript,
                len(nftScript),
                this.senderAddress
            )
            outputs = Utils.buildOutput(outputScript, nftOutputSatoshis)

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

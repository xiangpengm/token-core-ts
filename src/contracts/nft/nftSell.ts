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
    len,
    Tx,
    Sig,
} from 'scrypt-ts'
import { ProtoHeader } from '../protoheader'
import { NftProto } from './nftProto'

export class NftSell extends SmartContract {
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

    // 1 sell 2 cancel
    @method()
    public unlock(
        txPreimage: SigHashPreimage,
        nftScript: ByteString,
        senderPubKey: PubKey,
        senderSig: Sig,
        nftOutputSatoshis: bigint,
        op: bigint
    ) {
        let outputs = toByteString('')
        if (op == 1n) {
            const outputScript = Utils.buildPublicKeyHashScript(
                this.senderAddress
            )
            outputs = Utils.buildOutput(outputScript, this.mvcRecAmount)
        } else {
            // check sig
            assert(hash160(senderPubKey) == this.senderAddress)
            assert(this.checkSig(senderSig, senderPubKey))

            // verify nft
            const nftScriptLen = len(nftScript)
            assert(
                NftProto.getScriptCodeHash(nftScript, nftScriptLen) ==
                    this.nftCodeHash
            )
            assert(NftProto.getNftID(nftScript, nftScriptLen) == this.nftID)

            const outputScript = NftProto.getNewNftScript(
                nftScript,
                nftScriptLen,
                this.senderAddress
            )
            outputs = Utils.buildOutput(outputScript, nftOutputSatoshis)
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

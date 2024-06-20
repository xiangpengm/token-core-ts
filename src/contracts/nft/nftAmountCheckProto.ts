import { ByteString, method, prop, slice, SmartContractLib } from 'scrypt-ts'
import { ProtoHeader } from '../protoheader'

export class NftAmountCheckProto extends SmartContractLib {
    // dataPart: nftCodeHash + nftID
    @prop()
    static readonly OP_PUSH_LEN: bigint = 1n
    @prop()
    static readonly DATA_VERSION_LEN: bigint = 5n

    @prop()
    static readonly NFT_ID_OFFSET: bigint =
        ProtoHeader.DATA_VERSION_LEN + ProtoHeader.UNIQUE_ID_LEN
    @prop()
    static readonly NFT_CODE_HASH_OFFSET: bigint =
        NftAmountCheckProto.NFT_ID_OFFSET + ProtoHeader.HASH_LEN

    @prop()
    static readonly DATA_OFFSET: bigint =
        NftAmountCheckProto.NFT_CODE_HASH_OFFSET +
        NftAmountCheckProto.OP_PUSH_LEN

    @method()
    static getNftID(script: ByteString, slen: bigint): ByteString {
        return slice(
            script,
            slen - NftAmountCheckProto.NFT_ID_OFFSET,
            slen - NftAmountCheckProto.DATA_VERSION_LEN
        )
    }

    @method()
    static getNftCodeHash(script: ByteString, slen: bigint): ByteString {
        return slice(
            script,
            slen - NftAmountCheckProto.NFT_CODE_HASH_OFFSET,
            slen - NftAmountCheckProto.NFT_ID_OFFSET
        )
    }
}

import {
    ByteString,
    hash160,
    SmartContractLib,
    toByteString,
    slice,
    Utils,
    byteString2Int,
    method,
    prop,
} from 'scrypt-ts'
import { ProtoHeader } from '../protoheader'

export class NftProto extends SmartContractLib {
    @prop()
    static readonly PROTO_TYPE: bigint = 3n
    @prop()
    static readonly PROTO_VERSION: bigint = 1n
    @prop()
    static readonly BURN_ADDRESS: ByteString = toByteString(
        '0000000000000000000000000000000000000000'
    )
    @prop()
    static readonly OP_TRANSFER: bigint = 1n
    @prop()
    static readonly OP_UNLOCK_FROM_CONTRACT: bigint = 2n

    // <type specific data> + <proto header>
    //<nft type specific data> = <meta_outpoint(36 bytes)> + <address(20 bytes)> + <totalSupply(8 bytes) + <tokenIndex(8 bytes)> + <genesisHash<20 bytes>) + <GenesisTxid(36 bytes)>
    @prop()
    static readonly META_OUTPOINT_LEN: bigint = 36n
    @prop()
    static readonly OP_PUSH_LEN: bigint = 2n
    @prop()
    static readonly SENSIBLE_ID_OFFSET: bigint =
        ProtoHeader.PROTO_HEADER_OFFSET + ProtoHeader.GENESIS_TXID_LEN
    @prop()
    static readonly GENESIS_HASH_OFFSET: bigint =
        NftProto.SENSIBLE_ID_OFFSET + ProtoHeader.HASH_LEN
    @prop()
    static readonly TOKEN_INDEX_OFFSET: bigint =
        NftProto.GENESIS_HASH_OFFSET + ProtoHeader.AMOUNT_LEN
    @prop()
    static readonly TOTAL_SUPPLY_OFFSET: bigint =
        NftProto.TOKEN_INDEX_OFFSET + ProtoHeader.AMOUNT_LEN
    @prop()
    static readonly NFT_ADDRESS_OFFSET: bigint =
        NftProto.TOTAL_SUPPLY_OFFSET + ProtoHeader.ADDRESS_LEN
    @prop()
    static readonly META_OUTPOINT_OFFSET: bigint =
        NftProto.NFT_ADDRESS_OFFSET + NftProto.META_OUTPOINT_LEN

    @prop()
    static readonly DATA_LEN: bigint =
        NftProto.META_OUTPOINT_OFFSET + NftProto.OP_PUSH_LEN

    @method()
    static getGenesisTxid(script: ByteString, slen: bigint): ByteString {
        return slice(
            script,
            slen - NftProto.SENSIBLE_ID_OFFSET,
            slen - NftProto.SENSIBLE_ID_OFFSET + ProtoHeader.GENESIS_TXID_LEN
        )
    }

    @method()
    static getGenesisHash(script: ByteString, slen: bigint): ByteString {
        return slice(
            script,
            slen - NftProto.GENESIS_HASH_OFFSET,
            slen - NftProto.GENESIS_HASH_OFFSET + ProtoHeader.HASH_LEN
        )
    }

    @method()
    static getNftID(script: ByteString, slen: bigint): ByteString {
        return hash160(
            slice(
                script,
                slen - NftProto.TOKEN_INDEX_OFFSET,
                slen - ProtoHeader.PROTO_HEADER_OFFSET
            )
        )
    }

    @method()
    static getTokenIndex(script: ByteString, slen: bigint): bigint {
        return Utils.fromLEUnsigned(
            slice(
                script,
                slen - NftProto.TOKEN_INDEX_OFFSET,
                slen - NftProto.TOKEN_INDEX_OFFSET + ProtoHeader.AMOUNT_LEN
            )
        )
    }

    @method()
    static getTotalSupply(script: ByteString, slen: bigint): bigint {
        return Utils.fromLEUnsigned(
            slice(
                script,
                slen - NftProto.TOTAL_SUPPLY_OFFSET,
                slen - NftProto.TOTAL_SUPPLY_OFFSET + ProtoHeader.AMOUNT_LEN
            )
        )
    }

    @method()
    static getNftAddress(script: ByteString, slen: bigint): ByteString {
        return slice(
            script,
            slen - NftProto.NFT_ADDRESS_OFFSET,
            slen - NftProto.NFT_ADDRESS_OFFSET + ProtoHeader.ADDRESS_LEN
        )
    }

    @method()
    static getScriptCode(script: ByteString, slen: bigint): ByteString {
        // contract code include op_return
        return slice(script, 0n, slen - NftProto.DATA_LEN)
    }

    @method()
    static getScriptData(script: ByteString, slen: bigint): ByteString {
        return slice(script, slen - NftProto.DATA_LEN)
    }

    @method()
    static getScriptCodeHash(script: ByteString, slen: bigint): ByteString {
        return hash160(NftProto.getScriptCode(script, slen))
    }

    @method()
    static getNewNftScript(
        script: ByteString,
        slen: bigint,
        address: ByteString
    ): ByteString {
        return (
            slice(script, 0n, slen - NftProto.NFT_ADDRESS_OFFSET) +
            address +
            slice(
                script,
                slen - NftProto.NFT_ADDRESS_OFFSET + ProtoHeader.ADDRESS_LEN,
                slen
            )
        )
    }

    @method()
    static getNewNftScriptData(
        script: ByteString,
        slen: bigint,
        address: ByteString
    ): ByteString {
        return (
            slice(
                script,
                slen - NftProto.DATA_LEN,
                slen - NftProto.NFT_ADDRESS_OFFSET
            ) +
            address +
            slice(
                script,
                slen - NftProto.NFT_ADDRESS_OFFSET + ProtoHeader.ADDRESS_LEN,
                slen
            )
        )
    }

    @method()
    static checkDataLen(script: ByteString, slen: bigint): boolean {
        return (
            byteString2Int(
                slice(
                    script,
                    slen - NftProto.DATA_LEN + 1n,
                    slen - NftProto.DATA_LEN + 2n
                ) + toByteString('00')
            ) ==
            NftProto.DATA_LEN - NftProto.OP_PUSH_LEN
        )
    }

    @method()
    static checkOpReturn(script: ByteString, slen: bigint): boolean {
        return (
            slice(
                script,
                slen - NftProto.DATA_LEN - 1n,
                slen - NftProto.DATA_LEN
            ) == toByteString('6a')
        )
    }

    @method()
    static getNewGenesisScript(
        script: ByteString,
        slen: bigint,
        sensibleID: ByteString,
        tokenIndex: bigint
    ): ByteString {
        return (
            slice(script, 0n, slen - NftProto.TOKEN_INDEX_OFFSET) +
            Utils.toLEUnsigned(tokenIndex, 8n) +
            slice(
                script,
                slen - NftProto.GENESIS_HASH_OFFSET,
                slen - NftProto.SENSIBLE_ID_OFFSET
            ) +
            sensibleID +
            slice(script, slen - ProtoHeader.PROTO_HEADER_OFFSET)
        )
    }

    @method()
    static checkProtoHeader(script: ByteString, slen: bigint): boolean {
        return (
            slice(
                script,
                slen - ProtoHeader.PROTO_HEADER_OFFSET,
                slen - ProtoHeader.PROTO_HEADER_OFFSET + ProtoHeader.HEADER_LEN
            ) ==
            toByteString('0100000003000000') + ProtoHeader.PROTO_FLAG
        )
    }
}

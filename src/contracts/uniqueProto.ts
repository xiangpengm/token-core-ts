import {
    ByteString,
    prop,
    SmartContractLib,
    Utils,
    slice,
    hash160,
    method,
    len,
} from 'scrypt-ts'
import { ProtoHeader } from './protoheader'

export class UniqueProto extends SmartContractLib {
    // <op_pushdata> + <type specific data> + <proto header> + <data_len(4 bytes)> + <version(1 bytes)>
    // <proto header> = <proto_version(4 bytes)> + <proto_type(4 bytes)> + <'metacontract'(12 bytes)>
    // <unique type specific data> = <unique custom data> + <custom data length(4 bytes)> + <genesisTxid(36 bytes)>
    @prop()
    static readonly PROTO_FLAG: ByteString = ProtoHeader.PROTO_FLAG
    @prop()
    static readonly PROTO_TYPE: bigint = 2n
    @prop()
    static readonly PROTO_VERSION: bigint = 1n

    @prop()
    static readonly CUSTOM_DATA_SIZE_LEN: bigint = 4n

    @prop()
    static readonly GENESIS_TXID_OFFSET: bigint =
        ProtoHeader.PROTO_HEADER_OFFSET + ProtoHeader.GENESIS_TXID_LEN
    @prop()
    static readonly CUSTOM_DATA_SIZE_OFFSET: bigint =
        UniqueProto.GENESIS_TXID_OFFSET + UniqueProto.CUSTOM_DATA_SIZE_LEN

    @prop()
    static readonly FIX_HEADER_LEN: bigint = UniqueProto.CUSTOM_DATA_SIZE_OFFSET

    @method()
    static getUniqueID(script: ByteString, slen: bigint): ByteString {
        return hash160(
            slice(
                script,
                slen - UniqueProto.GENESIS_TXID_OFFSET,
                slen -
                    UniqueProto.GENESIS_TXID_OFFSET +
                    ProtoHeader.GENESIS_TXID_LEN
            )
        )
    }

    @method()
    static getGenesisTxid(script: ByteString, slen: bigint): ByteString {
        return slice(
            script,
            slen - UniqueProto.GENESIS_TXID_OFFSET,
            slen -
                UniqueProto.GENESIS_TXID_OFFSET +
                ProtoHeader.GENESIS_TXID_LEN
        )
    }

    @method()
    static getCustomDataLen(script: ByteString, slen: bigint): bigint {
        return Utils.fromLEUnsigned(
            slice(
                script,
                slen - UniqueProto.CUSTOM_DATA_SIZE_OFFSET,
                slen -
                    UniqueProto.CUSTOM_DATA_SIZE_OFFSET +
                    UniqueProto.CUSTOM_DATA_SIZE_LEN
            )
        )
    }

    @method()
    static getCustomData(script: ByteString, slen: bigint): ByteString {
        const customDataLen = UniqueProto.getCustomDataLen(script, slen)
        return slice(
            script,
            slen - UniqueProto.CUSTOM_DATA_SIZE_OFFSET - customDataLen,
            slen - UniqueProto.CUSTOM_DATA_SIZE_OFFSET
        )
    }

    @method()
    static getNewScriptWithCustomData(
        script: ByteString,
        slen: bigint,
        customData: ByteString
    ): ByteString {
        const customDataLen = UniqueProto.getCustomDataLen(script, slen)
        return (
            slice(
                script,
                0n,
                slen - UniqueProto.CUSTOM_DATA_SIZE_OFFSET - customDataLen
            ) +
            customData +
            Utils.toLEUnsigned(len(customData), 4n) +
            slice(
                script,
                slen -
                    UniqueProto.CUSTOM_DATA_SIZE_OFFSET +
                    UniqueProto.CUSTOM_DATA_SIZE_LEN
            )
        )
    }
}

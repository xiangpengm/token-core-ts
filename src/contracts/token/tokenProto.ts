import {
    ByteString,
    prop,
    method,
    hash160,
    SmartContractLib,
    toByteString,
    slice,
    Utils,
} from 'scrypt-ts'
import { ProtoHeader } from '../protoheader'

export class TokenProto extends SmartContractLib {
    @prop()
    static readonly OP_TRANSFER: bigint = 1n
    @prop()
    static readonly OP_UNLOCK_FROM_CONTRACT: bigint = 2n

    @prop()
    static readonly BURN_ADDRESS: ByteString = toByteString(
        '0000000000000000000000000000000000000000'
    )

    // proto type and version
    @prop()
    static readonly PROTO_TYPE: bigint = 1n
    @prop()
    static readonly PROTO_VERSION: bigint = 1n

    // <op_pushdata> + <type specific data> + <proto header> + <data_len(4 bytes)> + <version(1 bytes)>
    // <token type specific data> = <name(40 bytes)> + <symbol(20 bytes)> + <decimal(1 bytes)> + <address(20 bytes)> + <token amount(8 bytes)> + <genesisHash(20 bytes)> + <genesisTxid(36 bytes)>
    @prop()
    static readonly TOKEN_NAME_LEN: bigint = 40n
    @prop()
    static readonly TOKEN_SYMBOL_LEN: bigint = 20n
    @prop()
    static readonly TOKEN_DECIMAL_LEN: bigint = 1n

    // OP_PUSH_DATA(0x76) + data_len(1 byte) + data + OP_DROP
    @prop()
    static readonly OP_PUSH_LEN: bigint = 2n
    @prop()
    static readonly GENESIS_TXID_OFFSET: bigint =
        ProtoHeader.PROTO_HEADER_OFFSET + ProtoHeader.GENESIS_TXID_LEN
    @prop()
    static readonly GENESIS_HASH_OFFSET: bigint =
        TokenProto.GENESIS_TXID_OFFSET + ProtoHeader.HASH_LEN

    @prop()
    static readonly TOKEN_AMOUNT_OFFSET: bigint =
        TokenProto.GENESIS_HASH_OFFSET + ProtoHeader.AMOUNT_LEN
    @prop()
    static readonly TOKEN_ADDRESS_OFFSET: bigint =
        TokenProto.TOKEN_AMOUNT_OFFSET + ProtoHeader.ADDRESS_LEN
    @prop()
    static readonly TOKEN_DECIMAL_OFFSET: bigint =
        TokenProto.TOKEN_ADDRESS_OFFSET + TokenProto.TOKEN_DECIMAL_LEN
    @prop()
    static readonly TOKEN_SYMBOL_OFFSET: bigint =
        TokenProto.TOKEN_DECIMAL_OFFSET + TokenProto.TOKEN_SYMBOL_LEN
    @prop()
    static readonly TOKEN_NAME_OFFSET: bigint =
        TokenProto.TOKEN_SYMBOL_OFFSET + TokenProto.TOKEN_NAME_LEN
    // data_len include op_push
    static readonly DATA_LEN: bigint =
        TokenProto.TOKEN_NAME_OFFSET + TokenProto.OP_PUSH_LEN

    @method()
    static getTokenMetaData(script: ByteString, slen: bigint): ByteString {
        return slice(
            script,
            slen - TokenProto.TOKEN_NAME_OFFSET,
            slen -
                TokenProto.TOKEN_DECIMAL_OFFSET +
                TokenProto.TOKEN_DECIMAL_LEN
        )
    }

    @method()
    static getTokenAddress(script: ByteString, slen: bigint): ByteString {
        return slice(
            script,
            slen - TokenProto.TOKEN_ADDRESS_OFFSET,
            slen - TokenProto.TOKEN_AMOUNT_OFFSET
        )
    }

    @method()
    static getTokenAmount(script: ByteString, slen: bigint): bigint {
        return Utils.fromLEUnsigned(
            slice(
                script,
                slen - TokenProto.TOKEN_AMOUNT_OFFSET,
                slen - TokenProto.GENESIS_HASH_OFFSET
            )
        )
    }

    @method()
    static getGenesisHash(script: ByteString, slen: bigint): ByteString {
        return slice(
            script,
            slen - TokenProto.GENESIS_HASH_OFFSET,
            slen - TokenProto.GENESIS_TXID_OFFSET
        )
    }

    @method()
    static getGenesisTxid(script: ByteString, slen: bigint): ByteString {
        return slice(
            script,
            slen - TokenProto.GENESIS_TXID_OFFSET,
            slen - TokenProto.GENESIS_TXID_OFFSET + ProtoHeader.GENESIS_TXID_LEN
        )
    }

    @method()
    static getTokenID(script: ByteString, slen: bigint): ByteString {
        return hash160(
            slice(
                script,
                slen - TokenProto.GENESIS_HASH_OFFSET,
                slen -
                    TokenProto.GENESIS_TXID_OFFSET +
                    ProtoHeader.GENESIS_TXID_LEN
            )
        )
    }

    @method()
    static getNewTokenScript(
        script: ByteString,
        slen: bigint,
        address: ByteString,
        tokenValue: bigint
    ): ByteString {
        return (
            slice(script, 0n, slen - TokenProto.TOKEN_ADDRESS_OFFSET) +
            address +
            Utils.toLEUnsigned(tokenValue, 8n) +
            slice(script, slen - TokenProto.GENESIS_HASH_OFFSET)
        )
    }

    @method()
    static getNewTokenScriptData(
        script: ByteString,
        slen: bigint,
        address: ByteString,
        tokenAmount: bigint
    ): ByteString {
        return (
            slice(
                script,
                slen - TokenProto.DATA_LEN,
                slen - TokenProto.TOKEN_ADDRESS_OFFSET
            ) +
            address +
            Utils.toLEUnsigned(tokenAmount, 8n) +
            slice(script, slen - TokenProto.GENESIS_HASH_OFFSET)
        )
    }

    @method()
    static checkDataLen(script: ByteString, slen: bigint): boolean {
        return (
            slice(
                script,
                slen - TokenProto.DATA_LEN - 1n,
                slen - TokenProto.DATA_LEN
            ) == toByteString('6a') &&
            slice(
                script,
                slen - TokenProto.DATA_LEN,
                slen - TokenProto.DATA_LEN + 1n
            ) == toByteString('4c') &&
            Utils.fromLEUnsigned(
                slice(
                    script,
                    slen - TokenProto.DATA_LEN + 1n,
                    slen - TokenProto.DATA_LEN + 2n
                )
            ) ==
                TokenProto.DATA_LEN - TokenProto.OP_PUSH_LEN
        )
    }

    @method()
    static getScriptCode(script: ByteString, slen: bigint): ByteString {
        return slice(script, 0n, slen - TokenProto.DATA_LEN)
    }

    @method()
    static getScriptData(script: ByteString, slen: bigint): ByteString {
        return slice(script, slen - TokenProto.DATA_LEN)
    }

    @method()
    static getScriptCodeHash(script: ByteString, slen: bigint): ByteString {
        return hash160(TokenProto.getScriptCode(script, slen))
    }

    @method()
    static getNewGenesisScript(
        script: ByteString,
        slen: bigint,
        genesisTxid: ByteString
    ): ByteString {
        return (
            slice(script, 0n, slen - TokenProto.GENESIS_TXID_OFFSET) +
            genesisTxid +
            slice(
                script,
                slen -
                    TokenProto.GENESIS_TXID_OFFSET +
                    ProtoHeader.GENESIS_TXID_LEN
            )
        )
    }

    @method()
    static getNewTokenScriptFromGenesisData(
        script: ByteString,
        slen: bigint,
        address: ByteString,
        tokenAmount: bigint,
        genesisHash: ByteString
    ): ByteString {
        return (
            slice(script, 0n, slen - TokenProto.TOKEN_ADDRESS_OFFSET) +
            address +
            Utils.toLEUnsigned(tokenAmount, 8n) +
            genesisHash +
            slice(script, slen - TokenProto.GENESIS_TXID_OFFSET)
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
            toByteString('0100000001000000') + ProtoHeader.PROTO_FLAG
        )
    }
}

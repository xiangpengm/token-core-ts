import {
    toByteString,
    ByteString,
    prop,
    SmartContractLib,
    SigHash,
    SigHashType,
    Utils,
    slice,
    method,
} from 'scrypt-ts'

export class ProtoHeader extends SmartContractLib {
    // <proto header> = <proto_version(4 bytes)> + <proto_type(4 bytes)> + <'metacontract'(12 bytes)>
    @prop()
    static readonly PROTO_FLAG: ByteString = toByteString(
        '6d657461636f6e7472616374'
    ) // metacontract

    @prop()
    static readonly HASH_ID_LEN: bigint = 20n
    @prop()
    static readonly HASH_LEN: bigint = 20n
    @prop()
    static readonly GENESIS_TXID_LEN: bigint = 36n
    @prop()
    static readonly AMOUNT_LEN: bigint = 8n
    @prop()
    static readonly ADDRESS_LEN: bigint = 20n
    @prop()
    static readonly GENESIS_FLAG_LEN: bigint = 1n
    @prop()
    static readonly DATA_VERSION_LEN: bigint = 5n
    @prop()
    static readonly UNIQUE_ID_LEN: bigint = 20n
    @prop()
    static readonly TX_HASH_LEN: bigint = 32n
    @prop()
    static readonly BLOCK_NUM_LEN: bigint = 4n

    @prop()
    static readonly PROTO_VERSION_LEN: bigint = 4n
    @prop()
    static readonly PROTO_TYPE_LEN: bigint = 4n
    @prop()
    static readonly PROTO_FLAG_LEN: bigint = 12n

    @prop()
    static readonly HEADER_LEN: bigint = 20n

    @prop()
    static readonly NULL_GENESIS_TXID: ByteString = toByteString(
        '000000000000000000000000000000000000000000000000000000000000000000000000'
    )
    @prop()
    static readonly TX_VERSION: bigint = 10n

    @prop()
    static readonly NULL_ADDRESS: ByteString = toByteString(
        '0000000000000000000000000000000000000000'
    )

    @prop()
    static readonly SIG_HASH_ALL: SigHashType = SigHash.ALL
    @prop()
    static readonly SIG_HASH_SINGLE: SigHashType = SigHash.SINGLE

    @prop()
    static readonly PROTO_HEADER_OFFSET: bigint =
        ProtoHeader.HEADER_LEN + ProtoHeader.DATA_VERSION_LEN

    @method()
    static getScriptCode(script: ByteString, slen: bigint): ByteString {
        const dataLen =
            Utils.fromLEUnsigned(slice(script, slen - 5n, slen - 1n)) + 5n
        const scriptCode = slice(script, 0n, slen - dataLen)
        return scriptCode
    }
}

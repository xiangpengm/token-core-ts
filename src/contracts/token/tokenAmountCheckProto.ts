import { prop, SmartContractLib } from 'scrypt-ts'
import { ProtoHeader } from '../protoheader'

export class AmountCheckProto extends SmartContractLib {
    @prop()
    static readonly OP_PUSH_LEN: bigint = 2n
    @prop()
    static readonly DATA_VERSION_LEN: bigint = 5n

    @prop()
    static readonly TOKEN_ID_OFFSET: bigint =
        ProtoHeader.DATA_VERSION_LEN + ProtoHeader.UNIQUE_ID_LEN

    @prop()
    static readonly TOKEN_CODE_HASH_OFFSET: bigint =
        AmountCheckProto.TOKEN_ID_OFFSET + ProtoHeader.HASH_LEN

    @prop()
    static readonly NRECERIVERS_OFFSET: bigint =
        AmountCheckProto.TOKEN_CODE_HASH_OFFSET + 4n
}

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
} from 'scrypt-ts'
import { ProtoHeader } from '../protoheader'

export class TokenSell extends SmartContract {
    @prop()
    mvcRecAddr: Ripemd160

    @prop()
    mvcRecAmount: bigint

    constructor(mvcRecAddr: Ripemd160, mvcRecAmount: bigint) {
        super(...arguments)
        this.mvcRecAddr = mvcRecAddr
        this.mvcRecAmount = mvcRecAmount
    }

    @method()
    public unlock(txPreimage: SigHashPreimage) {
        assert(
            this.checkPreimageSigHashType(
                txPreimage,
                ProtoHeader.SIG_HASH_SINGLE
            )
        )
        const outputScript = Utils.buildPublicKeyHashScript(this.mvcRecAddr)
        const output = Utils.buildOutput(outputScript, this.mvcRecAmount)

        assert(hash256(output) == SigHash.hashOutputs(txPreimage))
    }
}

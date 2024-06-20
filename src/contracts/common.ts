import {
    ByteString,
    assert,
    len,
    SmartContractLib,
    method,
    slice,
    Utils,
    toByteString,
} from 'scrypt-ts'
import { TokenProto } from './token/tokenProto'

export class Common extends SmartContractLib {
    @method()
    static checkTokenInput(
        tokenID: ByteString,
        tokenScriptCodeHash: ByteString,
        address: ByteString,
        tokenScript: ByteString
    ): bigint {
        const tokenScriptLen = len(tokenScript)
        assert(tokenID == TokenProto.getTokenID(tokenScript, tokenScriptLen))
        assert(
            tokenScriptCodeHash ==
                TokenProto.getScriptCodeHash(tokenScript, tokenScriptLen)
        )
        assert(
            address == TokenProto.getTokenAddress(tokenScript, tokenScriptLen)
        )
        const tokenInputAmount = TokenProto.getTokenAmount(
            tokenScript,
            tokenScriptLen
        )
        return tokenInputAmount
    }

    @method()
    static checkTokenInput2(
        tokenID: ByteString,
        tokenScriptCodeHash: ByteString,
        tokenScript: ByteString
    ): bigint {
        const tokenScriptLen = len(tokenScript)
        assert(tokenID == TokenProto.getTokenID(tokenScript, tokenScriptLen))
        assert(
            tokenScriptCodeHash ==
                TokenProto.getScriptCodeHash(tokenScript, tokenScriptLen)
        )
        const tokenInputAmount = TokenProto.getTokenAmount(
            tokenScript,
            tokenScriptLen
        )
        return tokenInputAmount
    }

    @method()
    static genRefundOutputs(
        prevouts: ByteString,
        thisOutpoint: ByteString,
        tokenScript: ByteString,
        senderAddress: ByteString,
        tokenInputAmount: bigint,
        tokenOutputSatoshis: bigint,
        changeOutput: ByteString
    ): ByteString {
        // refund token to user

        // verify input script
        // only three inputs enabled in order:
        // 1. lockingContract
        // 2. token
        // 3. tokenUnlockContractCheck
        assert(len(prevouts) == 108n)
        assert(thisOutpoint == slice(prevouts, 0n, 36n))

        const newTokenScript = TokenProto.getNewTokenScript(
            tokenScript,
            len(tokenScript),
            senderAddress,
            tokenInputAmount
        )
        const tokenOutput = Utils.buildOutput(
            newTokenScript,
            tokenOutputSatoshis
        )

        const outputs = tokenOutput + changeOutput

        return outputs
    }

    @method()
    static changeToken(
        tokenInputAmount: bigint,
        tokenRemove: bigint,
        tokenScript: ByteString,
        address: ByteString,
        tokenOutputSatoshis: bigint
    ): ByteString {
        const changeTokenAmount = tokenInputAmount - tokenRemove
        let tokenChangeOutput = toByteString('')
        if (changeTokenAmount > 0n) {
            const newTokenScript2 = TokenProto.getNewTokenScript(
                tokenScript,
                len(tokenScript),
                address,
                changeTokenAmount
            )
            tokenChangeOutput = Utils.buildOutput(
                newTokenScript2,
                tokenOutputSatoshis
            )
        }
        return tokenChangeOutput
    }
}

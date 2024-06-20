import {
    ByteString,
    assert,
    len,
    SmartContractLib,
    hash160,
    sha256,
    slice,
    method,
} from 'scrypt-ts'
import { TxOutputProof, TxUtil } from './txUtil'
import { ProtoHeader } from './protoheader'

export class UniqueCommon extends SmartContractLib {
    @method()
    static verifyContractHashProof(
        prevouts: ByteString,
        // contract tx hash proof
        contractTxProof: TxOutputProof,
        contractTxScript: ByteString,
        // hash proof for main contract hash contract root
        mainContractHashRoot: ByteString,
        mainContractHashProof: ByteString,
        mainContractHashIndex: bigint
    ): boolean {
        // verify the contractTxProof
        assert(sha256(contractTxScript) == contractTxProof.scriptHash)
        const contractOutpoint = slice(prevouts, 0n, TxUtil.OUTPOINT_LEN)
        TxUtil.verifyTxOutput(contractTxProof, contractOutpoint)

        // verify main contract hash root
        const contractScriptCodeHash = hash160(
            ProtoHeader.getScriptCode(contractTxScript, len(contractTxScript))
        )
        assert(
            contractScriptCodeHash ==
                slice(
                    mainContractHashProof,
                    mainContractHashIndex * 20n,
                    (mainContractHashIndex + 1n) * 20n
                )
        )
        assert(mainContractHashRoot == hash160(mainContractHashProof))
        return true
    }
}

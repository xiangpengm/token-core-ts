import {
    ByteString,
    assert,
    hash256,
    SmartContractLib,
    method,
    slice,
} from 'scrypt-ts'
import { TxInputProof, TxOutputProof, TxUtil } from './txUtil'

export class Backtrace extends SmartContractLib {
    @method()
    static verify(
        outpoint: ByteString,
        txHeader: ByteString,
        prevTxInputIndex: bigint,
        prevTxProof: TxOutputProof,
        genesisTxid: ByteString,
        inputProof: TxInputProof
    ): boolean {
        // verify tx id
        assert(slice(outpoint, 0n, 32n) == hash256(txHeader))

        // verify the specified output of prevTx is an input of tx
        TxUtil.verifyTxInput(txHeader, prevTxInputIndex, inputProof)

        const prevOutpoint = inputProof.txHash + inputProof.outputIndexBytes
        if (prevOutpoint != genesisTxid) {
            // check if prevTx's script code is same with scriptCodeHash
            TxUtil.verifyTxOutput(prevTxProof, prevOutpoint)
        }

        return true
    }
}

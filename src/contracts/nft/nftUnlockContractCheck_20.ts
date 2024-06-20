import {
    method,
    assert,
    SmartContract,
    ByteString,
    Utils,
    len,
    sha256,
    hash256,
    SigHash,
    slice,
    toByteString,
    Tx,
    SigHashPreimage,
} from 'scrypt-ts'
import { TxOutputProof, TxUtil } from '../txUtil'
import { ProtoHeader } from '../protoheader'
import { NftProto } from './nftProto'
import { NftAmountCheckProto } from './nftAmountCheckProto'

export class NftUnlockContractCheck20 extends SmartContract {
    static readonly MAX_OUTPUT = 20

    @method()
    verifyOutput(
        output: ByteString,
        nftScriptLen: bigint,
        nftID: ByteString
    ): boolean {
        const b = slice(output, 8n)
        const n = Utils.fromLEUnsigned(slice(b, 0n, 1n))
        let sum = 0n
        let offset = 0n
        if (n < 0xfd) {
            sum = 1n + n
            offset = 1n
        } else if (n == 0xfdn) {
            sum = 3n + Utils.fromLEUnsigned(slice(b, 1n, 3n))
            offset = 3n
        } else if (n == 0xfen) {
            sum = 5n + Utils.fromLEUnsigned(slice(b, 1n, 5n))
            offset = 5n
        } else {
            // n == 0xff
            // not support 8 bytes length output
            //sum = 9 + Util.fromLEUnsigned(b[1:9]);
            //offset = 9;
            assert(false)
        }
        assert(len(output) == sum + 8n)
        // check if other output is the same token output
        const script = slice(output, 8n + offset)
        if (nftScriptLen == len(script)) {
            assert(NftProto.getNftID(script, nftScriptLen) != nftID)
        }
        return true
    }

    @method()
    public unlock(
        txPreimage: SigHashPreimage,
        prevouts: ByteString,
        // nft
        nftInputIndex: bigint,
        nftScript: ByteString,
        nftTxHeader: ByteString,
        nftTxHashProof: ByteString,
        nftSatoshiBytes: ByteString,
        // output
        nOutputs: bigint,
        txNftOutputIndex: bigint,
        nftOutputAddress: ByteString,
        nftOutputSatoshis: bigint,
        otherOutputArray: ByteString
    ) {
        assert(hash256(prevouts) == SigHash.hashPrevouts(txPreimage))

        const thisScript = SigHash.scriptCode(txPreimage)
        const scriptLen = len(thisScript)
        const nftID = NftAmountCheckProto.getNftID(thisScript, scriptLen)
        const nftCodeHash = NftAmountCheckProto.getNftCodeHash(
            thisScript,
            scriptLen
        )

        // verify nftScript
        const nftScriptLen = len(nftScript)
        const nftOutpoint = slice(
            prevouts,
            nftInputIndex * TxUtil.OUTPOINT_LEN,
            (nftInputIndex + 1n) * TxUtil.OUTPOINT_LEN
        )
        const nftProof: TxOutputProof = {
            txHeader: nftTxHeader,
            hashProof: nftTxHashProof,
            satoshiBytes: nftSatoshiBytes,
            scriptHash: sha256(nftScript),
        }
        TxUtil.verifyTxOutput(nftProof, nftOutpoint)

        assert(
            nftCodeHash == NftProto.getScriptCodeHash(nftScript, nftScriptLen)
        )
        assert(nftID == NftProto.getNftID(nftScript, nftScriptLen))
        const nftAddress = NftProto.getNftAddress(nftScript, nftScriptLen)

        let isBurn = false
        if (nftAddress == NftProto.BURN_ADDRESS) {
            isBurn = true
        } else {
            assert(txNftOutputIndex >= 0n)
            assert(txNftOutputIndex < nOutputs)
        }

        // check the outputs
        let outputs = toByteString('')
        // max support loop num receiver, you can change this num, but will cause the contrac size increase. you can customize your output
        let otherOutputIndex = 0n
        assert(nOutputs <= NftUnlockContractCheck20.MAX_OUTPUT)
        for (let i = 0; i < NftUnlockContractCheck20.MAX_OUTPUT; i++) {
            if (BigInt(i) < nOutputs) {
                if (BigInt(i) == txNftOutputIndex && isBurn == false) {
                    const outputScript = NftProto.getNewNftScript(
                        nftScript,
                        nftScriptLen,
                        nftOutputAddress
                    )
                    const output = Utils.buildOutput(
                        outputScript,
                        nftOutputSatoshis
                    )
                    outputs += output
                } else {
                    const outputLen = Utils.fromLEUnsigned(
                        slice(
                            otherOutputArray,
                            otherOutputIndex,
                            otherOutputIndex + 4n
                        )
                    )
                    const output = slice(
                        otherOutputArray,
                        otherOutputIndex + 4n,
                        otherOutputIndex + 4n + outputLen
                    )

                    // verify output
                    this.verifyOutput(output, nftScriptLen, nftID)

                    outputs += output
                    otherOutputIndex += 4n + outputLen
                }
            }
        }
        const hashOutputs = hash256(outputs)
        assert(hashOutputs == SigHash.hashOutputs(txPreimage))

        assert(
            Tx.checkPreimageSigHashTypeOCS(txPreimage, ProtoHeader.SIG_HASH_ALL)
        )
    }
}

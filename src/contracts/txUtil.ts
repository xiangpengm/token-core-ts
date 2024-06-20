import {
    len,
    prop,
    slice,
    assert,
    method,
    sha256,
    toByteString,
    Utils,
    Ripemd160,
    ByteString,
    SmartContractLib,
    hash256,
} from 'scrypt-ts'

export type LockingScriptParts = {
    code: ByteString
    data: ByteString
}

export type OpPushData = {
    len: bigint
    value: bigint
}

export type VarIntData = {
    len: bigint
    value: bigint
}

export type TxInputProof = {
    hashProof: ByteString
    txHash: ByteString
    outputIndexBytes: ByteString
    sequenceBytes: ByteString
}

export type TxOutputProof = {
    txHeader: ByteString
    hashProof: ByteString
    satoshiBytes: ByteString
    scriptHash: ByteString
}

export class TxUtil extends SmartContractLib {
    @prop()
    static readonly OUTPOINT_LEN: bigint = 36n
    @prop()
    static readonly TX_ID_LEN: bigint = 32n
    @prop()
    static readonly TX_HEADER_LEN: bigint = 112n

    @method()
    static verifyTxOutput(
        txProof: TxOutputProof,
        outpoint: ByteString
    ): boolean {
        assert(hash256(txProof.txHeader) == slice(outpoint, 0n, 32n))
        const outputIndex = Utils.fromLEUnsigned(slice(outpoint, 32n))

        const outputsLen = Utils.fromLEUnsigned(
            slice(txProof.txHeader, 12n, 16n)
        )
        const outputHashRoot = slice(txProof.txHeader, 80n, 112n)

        // verify hashProof
        assert(len(txProof.hashProof) == outputsLen * 40n)
        assert(sha256(txProof.hashProof) == outputHashRoot)

        // verify hashValue
        // checking one can confirm two
        // require(len(txProof.satoshiBytes) == 8);
        assert(len(txProof.scriptHash) == 32n)
        const hashValue = txProof.satoshiBytes + txProof.scriptHash

        assert(
            hashValue ==
                slice(
                    txProof.hashProof,
                    outputIndex * 40n,
                    (outputIndex + 1n) * 40n
                )
        )
        return true
    }

    @method()
    static verifyTxInput(
        txHeader: ByteString,
        inputIndex: bigint,
        proof: TxInputProof
    ): boolean {
        const inputsLen = Utils.fromLEUnsigned(slice(txHeader, 8n, 12n))
        const inputHashRoot = slice(txHeader, 16n, 48n)
        assert(inputIndex < inputsLen)

        // verify hashProof
        assert(len(proof.hashProof) == inputsLen * 40n)
        assert(sha256(proof.hashProof) == inputHashRoot)

        // verify hashValue
        // checking two can confirm three
        assert(len(proof.txHash) == 32n)
        assert(len(proof.outputIndexBytes) == 4n)

        const hashValue =
            proof.txHash + proof.outputIndexBytes + proof.sequenceBytes
        assert(
            hashValue ==
                slice(
                    proof.hashProof,
                    inputIndex * 40n,
                    (inputIndex + 1n) * 40n
                )
        )
        return true
    }

    @method()
    static getVarintLen(b: ByteString): bigint {
        let len = 0n
        const header = slice(b, 0n, 1n)
        if (header == toByteString('fd')) {
            len = 3n
        } else if (header == toByteString('fe')) {
            len = 5n
        } else if (header == toByteString('ff')) {
            len = 9n
        } else {
            len = 1n
        }
        return len
    }

    @method()
    static getVarIntData(b: ByteString): VarIntData {
        let len = 0n
        let value = 0n
        const header = slice(b, 0n, 1n)
        if (header == toByteString('fd')) {
            len = 3n
            value = Utils.fromLEUnsigned(slice(b, 1n, 3n))
        } else if (header == toByteString('fe')) {
            len = 5n
            value = Utils.fromLEUnsigned(slice(b, 1n, 5n))
        } else if (header == toByteString('ff')) {
            len = 9n
            value = Utils.fromLEUnsigned(slice(b, 1n, 9n))
        } else {
            len = 1n
            value = Utils.fromLEUnsigned(slice(b, 0n, 1n))
        }
        return { len, value }
    }

    @method()
    static getOpPushDataLen(b: ByteString): bigint {
        let len = 0n
        const header = slice(b, 0n, 1n)
        if (header == toByteString('4c')) {
            len = 2n
        } else if (header == toByteString('4d')) {
            len = 3n
        } else if (header == toByteString('4e')) {
            len = 5n
        } else {
            len = 1n
        }
        return len
    }

    @method()
    static decodeOpPushData(b: ByteString): OpPushData {
        let len = 0n
        let value = 0n
        const header = slice(b, 0n, 1n)
        if (header == toByteString('4c')) {
            len = 2n
            value = Utils.fromLEUnsigned(slice(b, 1n, 2n))
        } else if (header == toByteString('4d')) {
            len = 3n
            value = Utils.fromLEUnsigned(slice(b, 1n, 3n))
        } else if (header == toByteString('4e')) {
            len = 5n
            value = Utils.fromLEUnsigned(slice(b, 1n, 5n))
        } else {
            len = 1n
            value = Utils.fromLEUnsigned(header)
        }
        return { len, value }
    }

    @method()
    static getScriptCodeFromOutput(output: ByteString): ByteString {
        return Utils.readVarint(slice(output, 8n))
    }

    @method()
    static getVarOpLen(length: bigint): bigint {
        let res = 0n
        if (length <= 75n) {
            res = 1n
        } else if (length <= 255) {
            res = 2n
        } else if (length <= 65535) {
            res = 3n
        } else {
            res = 5n
        }
        return res
    }

    @method()
    static getVarOpLenOpt(length: bigint): bigint {
        let res = 0n
        if (length <= 75n) {
            res = 1n
        } else {
            res = 2n
        }
        return res
    }

    @method()
    static genMvcOutput(satoshis: bigint, address: Ripemd160): ByteString {
        let output = toByteString('')
        if (satoshis > 0n) {
            const outputScript = Utils.buildPublicKeyHashScript(address)
            output = Utils.buildOutput(outputScript, satoshis)
        }
        return output
    }
}

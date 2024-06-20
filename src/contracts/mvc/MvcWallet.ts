import {
    AddressOption,
    bsv as mvc,
    parseAddresses,
    SignatureRequest,
    SignatureResponse,
    Signer,
    UTXO,
    toHex,
} from 'scrypt-ts'
import { SignerAsync } from 'ecpair'
import { MvcProvider } from './MvcProvider'
const Interp = mvc.Script.Interpreter

export const DEFAULT_FLAGS =
    Interp.SCRIPT_ENABLE_MAGNETIC_OPCODES |
    Interp.SCRIPT_ENABLE_MONOLITH_OPCODES |
    Interp.SCRIPT_VERIFY_STRICTENC |
    Interp.SCRIPT_ENABLE_SIGHASH_FORKID |
    Interp.SCRIPT_VERIFY_LOW_S |
    Interp.SCRIPT_VERIFY_NULLFAIL |
    Interp.SCRIPT_VERIFY_DERSIG |
    Interp.SCRIPT_VERIFY_MINIMALDATA |
    Interp.SCRIPT_VERIFY_NULLDUMMY |
    Interp.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
    Interp.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
    Interp.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
    Interp.SCRIPT_VERIFY_CLEANSTACK

export const signatureToDer = function (r, s) {
    s = mvc.crypto.BN.fromHex(s)
    s = mvc.crypto.ECDSA.toLowS(s)
    const signature = {
        r: mvc.crypto.BN.fromHex(r),
        s: s,
    }
    return new mvc.crypto.Signature(signature.r, signature.s).toString()
}

const bufferSignature = function (ecBuffer: Buffer) {
    return {
        r: ecBuffer.subarray(0, 32).toString('hex'),
        s: ecBuffer.subarray(32, 64).toString('hex'),
    }
}

export async function signTxByAsyncSigner(
    tx: mvc.Transaction,
    signer: SignerAsync,
    lockingScript: mvc.Script,
    inputAmount: number,
    inputIndex = 0,
    sighashType = mvc.crypto.Signature.ALL,
    flags = DEFAULT_FLAGS
): Promise<string> {
    if (!tx) {
        throw new Error('param tx can not be empty')
    }

    if (!signer) {
        throw new Error('param privateKey can not be empty')
    }

    if (!lockingScript) {
        throw new Error('param lockingScript can not be empty')
    }

    if (!inputAmount) {
        throw new Error('param inputAmount can not be empty')
    }

    if (typeof lockingScript === 'string') {
        throw new Error(
            'Breaking change: LockingScript in ASM format is no longer supported, please use the lockingScript object directly'
        )
    }
    const hashBuf = mvc.Transaction.Sighash.sighash(
        tx,
        sighashType,
        inputIndex,
        lockingScript,
        new mvc.crypto.BN(inputAmount),
        flags
    )
    const sigRaw: Buffer = await signer.sign(hashBuf.reverse())
    const rs = bufferSignature(sigRaw)
    const der = signatureToDer(rs.r, rs.s)
    const sig = mvc.crypto.Signature.fromString(der)
    sig.set({
        nhashtype: sighashType,
    })
    return toHex(sig.toTxFormat())
}

export class MvcWallet extends Signer {
    private defaultEcSigner: SignerAsync
    private defaultEcSignerList: SignerAsync[]
    private readonly defaultPubkey: mvc.PublicKey
    private readonly defaultPubkeyList: mvc.PublicKey[]
    private readonly network: mvc.Networks.Network
    private readonly mvcProvider: MvcProvider

    constructor(
        ecSigner: SignerAsync,
        network: mvc.Networks.Network,
        provider: MvcProvider
    ) {
        super()
        this.defaultEcSigner = ecSigner
        this.defaultEcSignerList = [ecSigner]
        this.defaultPubkey = mvc.PublicKey.fromBuffer(ecSigner.publicKey)
        this.defaultPubkeyList = [this.defaultPubkey]
        this.network = network
        this.provider = provider
        this.mvcProvider = provider
    }

    public isProviderAutoSend() {
        return this.mvcProvider.autoSend
    }

    public clearCacheUtxoStore() {
        this.mvcProvider.clearCacheUtxoStore()
    }

    addEcSigner(ecSigner: SignerAsync) {
        const pubkey = mvc.PublicKey.fromBuffer(ecSigner.publicKey)
        this.defaultEcSignerList.push(ecSigner)
        this.defaultPubkeyList.push(pubkey)
        return this
    }

    async getDefaultAddress(): Promise<mvc.Address> {
        return this.defaultPubkey.toAddress(this.network)
    }

    async getDefaultPubKey(): Promise<mvc.PublicKey> {
        return this.defaultPubkey
    }

    async getNetwork(): Promise<mvc.Networks.Network> {
        return this.network
    }

    async getPubKey(address?: AddressOption): Promise<mvc.PublicKey> {
        if (address) {
            for (const pubkey of this.defaultPubkeyList) {
                if (
                    pubkey.toAddress(this.network).toString() ===
                    address.toString()
                ) {
                    return pubkey
                }
            }
            return undefined
        }
        return this.defaultPubkey
    }

    private getEcSignerList(
        address: mvc.Address | mvc.Address[]
    ): SignerAsync[] {
        if (!address) return [this.defaultEcSigner]
        const addresses = []
        if (address instanceof Array) {
            address.forEach((addr) => addresses.push(addr.toString()))
        } else {
            addresses.push(address.toString())
        }
        const ecSignerList = []
        for (let i = 0; i < this.defaultPubkeyList.length; i++) {
            const pubkey = this.defaultPubkeyList[i]
            const ecSigner = this.defaultEcSignerList[i]
            if (addresses.includes(pubkey.toAddress(this.network).toString())) {
                ecSignerList.push(ecSigner)
            }
        }
        return ecSignerList
    }

    async getSignatures(
        rawTxHex: string,
        sigRequests: SignatureRequest[]
    ): Promise<SignatureResponse[]> {
        const DEFAULT_SIGHASH_TYPE = mvc.crypto.Signature.ALL
        const tx = new mvc.Transaction(rawTxHex)
        const signatureResponseList: SignatureResponse[] = []
        for (const sigReq of sigRequests) {
            const script = sigReq.scriptHex
                ? new mvc.Script(sigReq.scriptHex)
                : mvc.Script.buildPublicKeyHashOut(
                      parseAddresses(sigReq.address, this.network)[0]
                  )
            tx.inputs[sigReq.inputIndex].output = new mvc.Transaction.Output({
                script: script,
                satoshis: sigReq.satoshis,
            })
            const ecSigners = this.getEcSignerList(sigReq.address)
            for (const ecSigner of ecSigners) {
                const subScript =
                    sigReq.csIdx !== undefined
                        ? script.subScript(sigReq.csIdx)
                        : script
                const sig = await signTxByAsyncSigner(
                    tx,
                    ecSigner,
                    subScript,
                    sigReq.satoshis,
                    sigReq.inputIndex,
                    sigReq.sigHashType
                )
                const item = {
                    sig: sig,
                    publicKey: ecSigner.publicKey.toString('hex'),
                    inputIndex: sigReq.inputIndex,
                    sigHashType: sigReq.sigHashType || DEFAULT_SIGHASH_TYPE,
                    csIdx: sigReq.csIdx,
                }
                signatureResponseList.push(item)
            }
        }
        return signatureResponseList
    }

    listUnspent(address: AddressOption): Promise<UTXO[]> {
        return this.provider.listUnspent(address)
    }

    async isAuthenticated(): Promise<boolean> {
        return true
    }

    async requestAuth(): Promise<{ isAuthenticated: boolean; error: string }> {
        return { error: '', isAuthenticated: true }
    }

    setProvider(provider: MvcProvider): void {
        this.provider = provider
    }

    signMessage(message: string, address?: AddressOption): Promise<string> {
        message
        address
        throw new Error('Method #signMessage not implemented.')
    }
}

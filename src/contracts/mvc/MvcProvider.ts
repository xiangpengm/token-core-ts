import {
    AddressOption,
    bsv as mvc,
    Provider,
    TransactionResponse,
    TxHash,
    UTXO,
} from 'scrypt-ts'
import { Api, API_NET, API_TARGET } from 'meta-contract'

export class MvcProvider extends Provider {
    public api: Api
    private apiMap: Map<mvc.Networks.Network, Api>
    private network: mvc.Networks.Network
    private feeRate: number
    public autoSend: boolean
    private cacheUtxoStore: Map<string, UTXO[]>

    constructor(
        apiTarget: API_TARGET,
        network: mvc.Networks.Network,
        feePerKb: number,
        autoSend: boolean = false
    ) {
        super()
        this.apiMap = new Map<mvc.Networks.Network, Api>()
        this.apiMap.set(mvc.Networks.livenet, new Api(API_NET.MAIN, apiTarget))
        this.apiMap.set(mvc.Networks.testnet, new Api(API_NET.TEST, apiTarget))
        this.api = this.apiMap.get(network)
        this.network = network
        this.feeRate = feePerKb
        this.autoSend = autoSend
        this.cacheUtxoStore = new Map<string, UTXO[]>()
    }

    async connect(): Promise<this> {
        return this
    }

    public clearCacheUtxoStore() {
        this.cacheUtxoStore = new Map<string, UTXO[]>()
    }

    setAddressUtxo(address: mvc.Address, utxoList: UTXO[]) {
        this.cacheUtxoStore.set(address.hashBuffer.toString('hex'), utxoList)
    }

    async getBalance(
        address?: AddressOption
    ): Promise<{ confirmed: number; unconfirmed: number }> {
        const info = await this.api.getBalance(address.toString())
        return { confirmed: info.balance, unconfirmed: info.pendingBalance }
    }

    async getFeePerKb(): Promise<number> {
        return this.feeRate
    }

    getNetwork(): mvc.Networks.Network {
        return this.network
    }

    async getTransaction(txHash: TxHash): Promise<TransactionResponse> {
        const rawTx = await this.api.getRawTxData(txHash)
        return new mvc.Transaction(rawTx)
    }

    isConnected(): boolean {
        return true
    }

    async listUnspent(address: AddressOption): Promise<UTXO[]> {
        const cacheUtxo = this.cacheUtxoStore.get(
            address.hashBuffer.toString('hex')
        )
        if (cacheUtxo && cacheUtxo.length > 0) {
            return cacheUtxo
        }
        const saUtxoList = await this.api.getUnspents(address.toString())
        const utxos: UTXO[] = []
        const script = mvc.Script.buildPublicKeyHashOut(address).toHex()
        for (const saUtxo of saUtxoList) {
            utxos.push({
                address: saUtxo.address,
                txId: saUtxo.txId,
                outputIndex: saUtxo.outputIndex,
                satoshis: saUtxo.satoshis,
                script: script,
            })
        }
        return utxos
    }

    async sendRawTransaction(rawTxHex: string): Promise<TxHash> {
        if (this.autoSend) {
            return await this.api.broadcast(rawTxHex)
        } else {
            const tx = new mvc.Transaction(rawTxHex)
            for (let i = 0; i < tx.outputs.length; i++) {
                const output = tx.outputs[i]
                if (output.script.isPublicKeyHashOut()) {
                    const address = output.script.toAddress(this.network)
                    const utxo = {
                        address: address.toString(),
                        txId: tx.hash,
                        outputIndex: i,
                        script: output.script.toHex(),
                        satoshis: output.satoshis,
                    }
                    this.setAddressUtxo(address, [utxo])
                }
            }
        }
    }

    updateNetwork(network: mvc.Networks.Network): void {
        this.network = network
        this.api = this.apiMap.get(network)
    }

    updateFeeRate(feeRate: number) {
        this.feeRate = feeRate
    }
}

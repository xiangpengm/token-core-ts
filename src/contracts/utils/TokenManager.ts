import {
    ByteString,
    ContractTransaction,
    FixedArray,
    MethodCallOptions,
    Signer,
    SmartContract,
    findSig,
    hash160,
    toByteString,
} from 'scrypt-ts'
import {
    ProtoHeader,
    Token,
    TokenGenesis,
    TokenProto,
    TokenTransferCheck,
    TokenTransferCheck10To10,
    TokenTransferCheck20To3,
    TokenTransferCheck3To100,
    TokenTransferCheck6To6,
    TokenUnlockContractCheck,
    TokenUnlockContractCheck20To5,
    TokenUnlockContractCheck3To100,
    TokenUnlockContractCheck4To8,
    TokenUnlockContractCheck8To12,
} from '../'
import { bsv as mvc } from 'scrypt-ts'
import { genDummyUtxo } from './txHelper'
import {
    buildScriptData,
    genSensibleIdAndUniqueId,
    getTxInputProof,
    getTxOutputProof,
    getUInt32Buf,
    getUInt64Buf,
    getUInt8Buf,
} from './Common'

const tokenType = getUInt32Buf(Number(TokenProto.PROTO_TYPE))
const tokenVersion = getUInt32Buf(Number(TokenProto.PROTO_VERSION))

export enum TokenTransferType {
    IN_3_OUT_3,
    IN_6_OUT_6,
    IN_10_OUT_10,
    IN_20_OUT_3,
    IN_3_OUT_100,
    UNSUPPORT,
}

const tokenTransferTypeInfos = [
    {
        type: TokenTransferType.IN_3_OUT_3,
        in: 3,
        out: 3,
        lockingScriptSize: 0,
    },
    {
        type: TokenTransferType.IN_6_OUT_6,
        in: 6,
        out: 6,
        lockingScriptSize: 0,
    },
    {
        type: TokenTransferType.IN_10_OUT_10,
        in: 10,
        out: 10,
        lockingScriptSize: 0,
    },
    {
        type: TokenTransferType.IN_20_OUT_3,
        in: 20,
        out: 3,
        lockingScriptSize: 0,
    },
    {
        type: TokenTransferType.IN_3_OUT_100,
        in: 3,
        out: 100,
        lockingScriptSize: 0,
    },
]

export enum TokenUnlockType {
    IN_2_OUT_5,
    IN_4_OUT_8,
    IN_8_OUT_12,
    IN_20_OUT_5,
    IN_3_OUT_100,
    UNSUPPORT,
}

const tokenUnlockTypeInfos = [
    {
        type: TokenUnlockType.IN_2_OUT_5,
        in: 2,
        out: 5,
    },
    {
        type: TokenUnlockType.IN_4_OUT_8,
        in: 4,
        out: 8,
    },
    {
        type: TokenUnlockType.IN_8_OUT_12,
        in: 8,
        out: 12,
    },
    {
        type: TokenUnlockType.IN_20_OUT_5,
        in: 20,
        out: 5,
    },
    {
        type: TokenUnlockType.IN_3_OUT_100,
        in: 3,
        out: 100,
    },
]

export class TokenGenesisManager {
    signer: Signer
    tokenManager: TokenManager
    tokenGenesis: TokenGenesis
    preDeployTx: mvc.Transaction
    deployTx: mvc.Transaction
    preGenesisTx: mvc.Transaction
    genesisTx: mvc.Transaction
    txStore: Map<string, mvc.Transaction>
    constructor(
        createSigner: Signer,
        tokenManager: TokenManager,
        tokenGenesis: TokenGenesis,
        preDeployTx: mvc.Transaction,
        deployTx: mvc.Transaction
    ) {
        this.signer = createSigner
        this.tokenManager = tokenManager
        this.tokenGenesis = tokenGenesis
        this.preDeployTx = preDeployTx
        this.deployTx = deployTx
        this.preGenesisTx = preDeployTx
        this.genesisTx = deployTx
        this.txStore = new Map<string, mvc.Transaction>()
        this.txStore.set(preDeployTx.hash, preDeployTx)
        this.txStore.set(deployTx.hash, deployTx)
    }

    createToken(amount: number, address: Buffer) {
        const token = new Token(
            this.tokenManager.tokenTransferCheckCodeHashArray,
            this.tokenManager.tokenUnlockContractCheckCodeHashArray
        )
        const locking = this.tokenGenesis.lockingScript.toHex()
        const slen = BigInt(locking.length / 2)
        const meta = TokenProto.getTokenMetaData(locking, slen)
        const [sensibleId] = genSensibleIdAndUniqueId(this.deployTx.hash, 0)
        const newGenesisScript = TokenProto.getNewGenesisScript(
            locking,
            slen,
            sensibleId
        )
        const genesisHash = hash160(newGenesisScript)
        const data = buildScriptData(
            Buffer.concat([
                Buffer.from(meta, 'hex'),
                address, // address
                getUInt64Buf(amount), // token value
                Buffer.from(genesisHash, 'hex'),
                Buffer.from(sensibleId, 'hex'),
                tokenVersion,
                tokenType,
                Buffer.from(ProtoHeader.PROTO_FLAG, 'hex'),
            ])
        )
        token.setDataPartInASM(data.toString('hex'))
        return token
    }

    async issue(amount: number, address: Buffer) {
        const genesis = TokenGenesis.fromTx(this.genesisTx, 0)
        const change = this.genesisTx.outputs[this.genesisTx.outputs.length - 1]
        const addressString = (await this.signer.getDefaultAddress()).toString()
        const utxo = {
            address: addressString,
            txId: this.genesisTx.hash,
            outputIndex: this.genesisTx.outputs.length - 1,
            script: mvc.Script.buildPublicKeyHashOut(addressString).toHex(),
            satoshis: change.satoshis,
        }
        await genesis.connect(this.signer)
        const newToken = this.createToken(amount, address)
        genesis.bindTxBuilder(
            'unlock',
            async (current: TokenGenesis): Promise<ContractTransaction> => {
                const tx = new mvc.Transaction()
                const defaultChangeAddress =
                    await current.signer.getDefaultAddress()
                const lockingScript = genesis.lockingScript.toHex()
                const slen = BigInt(lockingScript.length / 2)
                const sensibleID = TokenProto.getGenesisTxid(
                    lockingScript,
                    slen
                )
                let nextInstance = TokenGenesis.fromLockingScript(lockingScript)
                if (sensibleID == ProtoHeader.NULL_GENESIS_TXID) {
                    const [newSensibleId] = genSensibleIdAndUniqueId(
                        this.deployTx.hash,
                        0
                    )
                    const newLockingScript = TokenProto.getNewGenesisScript(
                        lockingScript,
                        slen,
                        newSensibleId
                    )
                    nextInstance =
                        TokenGenesis.fromLockingScript(newLockingScript)
                }

                tx.addInput(current.buildContractInput())
                tx.from(utxo)
                tx.addOutput(
                    new mvc.Transaction.Output({
                        script: nextInstance.lockingScript,
                        satoshis: current.balance,
                    })
                )
                tx.addOutput(
                    new mvc.Transaction.Output({
                        script: newToken.lockingScript,
                        satoshis: 1,
                    })
                )
                tx.change(defaultChangeAddress)
                return {
                    tx: tx,
                    atInputIndex: 0,
                    nexts: [
                        {
                            instance: nextInstance,
                            balance: current.balance,
                            atOutputIndex: 0,
                        },
                    ],
                }
            }
        )
        const ownerPubkey = await this.signer.getDefaultPubKey()
        const genesisTxHeader = getTxInputProof(this.genesisTx, 0)
        const prevGenesisTxHeader = getTxOutputProof(this.preGenesisTx, 0)
        const finalTx = await genesis.methods.unlock(
            '', // txPreimage
            ownerPubkey.toString(),
            (sigResps) => findSig(sigResps, ownerPubkey),
            newToken.lockingScript.toHex(),

            genesisTxHeader.txHeader,
            0n,
            genesisTxHeader.inputProofInfo,

            prevGenesisTxHeader.txHeader,
            prevGenesisTxHeader.hashProof,
            prevGenesisTxHeader.satoshiBytes,

            1n, // new genesis satoshi
            1n, // new token satoshi
            '', // changeAddress
            0n, // changeSatoshi
            '',
            {
                pubKeyOrAddrToSign: ownerPubkey,
                multiContractCall: true,
            } as MethodCallOptions<TokenGenesis>
        )
        const callContract = async () =>
            SmartContract.multiContractCall(finalTx, this.signer)
        await callContract()
        this.preGenesisTx = this.genesisTx
        this.genesisTx = finalTx.tx
        this.txStore.set(this.genesisTx.hash, this.genesisTx)
        return {
            token: Token.fromTx(finalTx.tx, 1),
            tx: finalTx.tx,
            preTx: this.preGenesisTx,
            preInput: 0,
            outputIndex: 1,
        }
    }
}

export class TokenManager {
    tokenTransferCheckContractArray: SmartContract[]
    tokenTransferCheckCodeHashArray: FixedArray<ByteString, 5>
    tokenUnlockContractCheckArray: SmartContract[]
    tokenUnlockContractCheckCodeHashArray: FixedArray<ByteString, 5>

    constructor(
        tokenTransferCheckContractArray: SmartContract[],
        tokenTransferCheckCodeHashArray: FixedArray<ByteString, 5>,
        tokenUnlockContractCheckArray: SmartContract[],
        tokenUnlockContractCheckCodeHashArray: FixedArray<ByteString, 5>
    ) {
        this.tokenTransferCheckContractArray = tokenTransferCheckContractArray
        this.tokenTransferCheckCodeHashArray = tokenTransferCheckCodeHashArray
        this.tokenUnlockContractCheckArray = tokenUnlockContractCheckArray
        this.tokenUnlockContractCheckCodeHashArray =
            tokenUnlockContractCheckCodeHashArray
    }

    static async loadArtifactAll() {
        await Token.loadArtifact(
            './node_modules/token-core-ts/artifacts/token/token.json'
        )
        await TokenGenesis.loadArtifact(
            './node_modules/token-core-ts/artifacts/token/tokenGenesis.json'
        )
        // token transfer check
        await TokenTransferCheck.loadArtifact(
            './node_modules/token-core-ts/artifacts/token/tokenTransferCheck.json'
        )
        await TokenTransferCheck3To100.loadArtifact(
            './node_modules/token-core-ts/artifacts/token/tokenTransferCheck_3To100.json'
        )
        await TokenTransferCheck6To6.loadArtifact(
            './node_modules/token-core-ts/artifacts/token/tokenTransferCheck_6To6.json'
        )
        await TokenTransferCheck10To10.loadArtifact(
            './node_modules/token-core-ts/artifacts/token/tokenTransferCheck_10To10.json'
        )
        await TokenTransferCheck20To3.loadArtifact(
            './node_modules/token-core-ts/artifacts/token/tokenTransferCheck_20To3.json'
        )
        // token contract check
        await TokenUnlockContractCheck.loadArtifact(
            './node_modules/token-core-ts/artifacts/token/tokenUnlockContractCheck.json'
        )
        await TokenUnlockContractCheck3To100.loadArtifact(
            './node_modules/token-core-ts/artifacts/token/tokenUnlockContractCheck_3To100.json'
        )
        await TokenUnlockContractCheck4To8.loadArtifact(
            './node_modules/token-core-ts/artifacts/token/tokenUnlockContractCheck_4To8.json'
        )
        await TokenUnlockContractCheck8To12.loadArtifact(
            './node_modules/token-core-ts/artifacts/token/tokenUnlockContractCheck_8To12.json'
        )
        await TokenUnlockContractCheck20To5.loadArtifact(
            './node_modules/token-core-ts/artifacts/token/tokenUnlockContractCheck_20To5.json'
        )
    }

    static async create() {
        await TokenManager.loadArtifactAll()
        const tokenTransferCheckContractArray = [
            new TokenTransferCheck(), // 3 to 3
            new TokenTransferCheck6To6(), // 6 to 6
            new TokenTransferCheck10To10(), // 10 to 10
            new TokenTransferCheck20To3(), // 20 to 3
            new TokenTransferCheck3To100(), // 3 to 100
        ]
        const tokenTransferCheckCodeHashArray: FixedArray<ByteString, 5> =
            tokenTransferCheckContractArray.map((value) =>
                toByteString(hash160(value.lockingScript.toHex() + '6a'))
            ) as unknown as any
        const tokenUnlockContractCheckArray = [
            new TokenUnlockContractCheck(), // 2 to 5
            new TokenUnlockContractCheck4To8(), // 4 to 8
            new TokenUnlockContractCheck8To12(), // 8 to 12
            new TokenUnlockContractCheck20To5(), // 20 to 5
            new TokenUnlockContractCheck3To100(), // 3 to 100
        ]
        const tokenUnlockContractCheckCodeHashArray: FixedArray<ByteString, 5> =
            tokenUnlockContractCheckArray.map((value) => {
                return toByteString(hash160(value.lockingScript.toHex() + '6a'))
            }) as unknown as any
        return new TokenManager(
            tokenTransferCheckContractArray,
            tokenTransferCheckCodeHashArray,
            tokenUnlockContractCheckArray,
            tokenUnlockContractCheckCodeHashArray
        )
    }

    async createGenesis(
        signer: Signer,
        name: string,
        symbol: string,
        decimal: number,
        issuerAddress: mvc.Address
    ) {
        const genesis = new TokenGenesis()
        const { utxo, tx } = await genDummyUtxo(signer)
        await genesis.connect(signer)
        const tokenName = Buffer.alloc(40, 0)
        tokenName.write(name)
        const tokenSymbol = Buffer.alloc(20, 0)
        tokenSymbol.write(symbol)
        const data = buildScriptData(
            Buffer.concat([
                tokenName,
                tokenSymbol,
                getUInt8Buf(decimal),
                issuerAddress.hashBuffer, // address
                Buffer.alloc(8, 0), // token value
                Buffer.alloc(20, 0), // genesisHash
                Buffer.from(ProtoHeader.NULL_GENESIS_TXID, 'hex'),
                tokenVersion,
                tokenType,
                Buffer.from(ProtoHeader.PROTO_FLAG, 'hex'),
            ])
        )
        genesis.setDataPartInASM(data.toString('hex'))
        const deployTx = await genesis.deploy(1, {
            utxos: [utxo],
        })
        return new TokenGenesisManager(signer, this, genesis, tx, deployTx)
    }

    selectTokenTransferCheck(inCount: number, outCount: number) {
        const typeInfo = tokenTransferTypeInfos.find(
            (v) => inCount <= v.in && outCount <= v.out
        )
        if (!typeInfo) {
            return TokenTransferType.UNSUPPORT
        }
        return typeInfo.type
    }

    selectTokenUnlockCheck(inCount: number, outCount: number) {
        const typeInfo = tokenUnlockTypeInfos.find(
            (v) => inCount <= v.in && outCount <= v.out
        )
        if (!typeInfo) {
            return TokenUnlockType.UNSUPPORT
        }
        return typeInfo.type
    }

    tokenCheckNewDataPart(dataPart: any): string {
        const nSendersBuf = getUInt32Buf(dataPart.nSenders)
        let receiverTokenAmountArrayBuf = Buffer.alloc(0)
        dataPart.receiverTokenAmountArray.forEach((tokenAmount: any) => {
            receiverTokenAmountArrayBuf = Buffer.concat([
                receiverTokenAmountArrayBuf,
                tokenAmount.toBuffer({ endian: 'little', size: 8 }),
            ])
        })
        let receiverArrayBuf = Buffer.alloc(0)
        dataPart.receiverArray.map((address) => {
            receiverArrayBuf = Buffer.concat([
                receiverArrayBuf,
                address.hashBuffer,
            ])
        })
        const nReceiversBuf = getUInt32Buf(dataPart.nReceivers)
        const tokenCodeHashBuf = Buffer.from(dataPart.tokenCodeHash, 'hex')
        const tokenIDBuf = Buffer.from(dataPart.tokenID, 'hex')
        const buf = Buffer.concat([
            nSendersBuf,
            receiverTokenAmountArrayBuf,
            receiverArrayBuf,
            nReceiversBuf,
            tokenCodeHashBuf,
            tokenIDBuf,
        ])

        return buildScriptData(buf).toString('hex')
    }

    tokenContractNewDataPart(dataPart: any) {
        const nTokenInputsBuf = getUInt32Buf(dataPart.nTokenInputs)
        const nTokenOutputsBuf = getUInt32Buf(dataPart.nTokenOutputs)
        let tokenInputIndexBytes = Buffer.alloc(0)
        for (let i = 0; i < dataPart.nTokenInputs; i++) {
            tokenInputIndexBytes = Buffer.concat([
                tokenInputIndexBytes,
                getUInt32Buf(dataPart.tokenInputIndexArray[i]),
            ])
        }

        let receiverTokenAmountArrayBuf = Buffer.alloc(0)
        dataPart.receiverTokenAmountArray.forEach((tokenAmount: any) => {
            receiverTokenAmountArrayBuf = Buffer.concat([
                receiverTokenAmountArrayBuf,
                tokenAmount.toBuffer({ endian: 'little', size: 8 }),
            ])
        })
        let receiverArrayBuf = Buffer.alloc(0)
        dataPart.receiverArray.map((address) => {
            receiverArrayBuf = Buffer.concat([
                receiverArrayBuf,
                address.hashBuffer,
            ])
        })
        const tokenCodeHashBuf = Buffer.from(dataPart.tokenCodeHash, 'hex')
        const tokenIDBuf = Buffer.from(dataPart.tokenID, 'hex')
        const buf = Buffer.concat([
            tokenInputIndexBytes,
            nTokenInputsBuf,
            receiverTokenAmountArrayBuf,
            receiverArrayBuf,
            nTokenOutputsBuf,
            tokenCodeHashBuf,
            tokenIDBuf,
        ])
        return buildScriptData(buf).toString('hex')
    }

    fromTx(tx: mvc.Transaction, outputIndex: number) {
        const token = new Token(
            this.tokenTransferCheckCodeHashArray,
            this.tokenUnlockContractCheckCodeHashArray
        )
        token.delegateInstance.replaceLocking(tx.outputs[outputIndex].script)
        token.from = {
            tx: tx,
            outputIndex: outputIndex,
        }
        return token
    }

    fromLockingScript(newLocking: mvc.Script | ByteString) {
        const token = new Token(
            this.tokenTransferCheckCodeHashArray,
            this.tokenUnlockContractCheckCodeHashArray
        )
        token.delegateInstance.replaceLocking(newLocking)
        return token
    }
}

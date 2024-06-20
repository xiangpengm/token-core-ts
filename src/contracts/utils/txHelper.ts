import {
    DummyProvider,
    DefaultProvider,
    TestWallet,
    bsv as mvc,
    Signer,
} from 'scrypt-ts'

import * as dotenv from 'dotenv'

// Load the .env file
dotenv.config()

const key1 = 'cReKmkHQn8ejr8Kun9miTceTSUpqa77jpQysnbgyxgU3HSu7T9cG'
const key2 = 'cQPQkyGSzoCfh4gAWJHN2oa4YtQSUekAtocZ2KVMoUobvTAiSuD9'
const key3 = 'cNYMFfzbLxSJ8Xgswu8Qk1rVHEx9aRpd88gYc15VhaovAh1Epf4Y'
const key4 = 'L2EQAX1V5iABhALGwPctQ7HRbXT88JF56tn1kcjNGK971GHogohW'
const key5 = 'KyXkuPyKe3cgW7JMz7Uj3ANGZEr1ycEbJKWjJgA9FTE16GRQrugQ'
const key6 = 'L4xofJN6ibvvAiq7KYPPGg52jEh3GPnvYY5GN4Lr3SqYLZsshbEE'
const key7 = 'KzCcZVzVXd6X1QJXvxDtz8RdMezkipd9jQYKPYqxcBtyjwkPvftf'

const myPrivateKey = mvc.PrivateKey.fromWIF(key1)

const wallets: Record<string, TestWallet> = {
    testnet: new TestWallet(
        myPrivateKey,
        new DefaultProvider({
            network: mvc.Networks.testnet,
        })
    ),
    local: new TestWallet(myPrivateKey, new DummyProvider()),
    mainnet: new TestWallet(
        myPrivateKey,
        new DefaultProvider({
            network: mvc.Networks.mainnet,
        })
    ),
}
export function getDefaultSigner(
    privateKey?: mvc.PrivateKey | mvc.PrivateKey[]
): TestWallet {
    const network = process.env.NETWORK || 'local'

    const wallet = wallets[network]

    if (privateKey) {
        wallet.addPrivateKey(privateKey)
    }

    return wallet
}

export const sleep = async (seconds: number) => {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve({})
        }, seconds * 1000)
    })
}

export function randomPrivateKey() {
    const privateKey = mvc.PrivateKey.fromRandom(mvc.Networks.testnet)
    const publicKey = mvc.PublicKey.fromPrivateKey(privateKey)
    const publicKeyHash = mvc.crypto.Hash.sha256ripemd160(publicKey.toBuffer())
    const address = publicKey.toAddress()
    return [privateKey, publicKey, publicKeyHash, address] as const
}

const dummyTxHex =
    '0a00000001a10808dc98547cef1e80a2993d91450689e9dfc4b356c996637384b999be0c7c010000006b483045022100d3c1fd14b5493fad7b766036db4d10fd9de2aad0dd2c504b2836b75663ad761802201b52a44523a949b164999a95e693aa62debeb9128383e3acb55757539505945a4121037155ee4f0beea84f97a409f2fbd20021329ef3ab135e0cbdf899645207905949ffffffff0200e40b54020000001976a91446d522ae9cc9856d975c37daeed569fd881b54ec88ac5e8606a6080000001976a91446d522ae9cc9856d975c37daeed569fd881b54ec88ac00000000'

export const genDummyUtxo = async (
    wallet: Signer
): Promise<{ utxo: mvc.Transaction.IUnspentOutput; tx: mvc.Transaction }> => {
    const address = await wallet.getDefaultAddress()
    const script = mvc.Script.buildPublicKeyHashOut(address).toHex()
    const tx = new mvc.Transaction(dummyTxHex)
    tx.outputs[0].setScript(script)
    const utxo = {
        address: address.toString(),
        txId: tx.hash,
        outputIndex: 0,
        script: script,
        satoshis: tx.outputs[0].satoshis,
    }
    return { utxo, tx }
}

export const wallet1 = new TestWallet(
    mvc.PrivateKey.fromWIF(key1),
    new DummyProvider()
)
export const wallet2 = new TestWallet(
    mvc.PrivateKey.fromWIF(key2),
    new DummyProvider()
)
export const wallet3 = new TestWallet(
    mvc.PrivateKey.fromWIF(key3),
    new DummyProvider()
)
export const wallet4 = new TestWallet(
    mvc.PrivateKey.fromWIF(key4),
    new DummyProvider()
)
export const wallet5 = new TestWallet(
    mvc.PrivateKey.fromWIF(key5),
    new DummyProvider()
)
export const wallet6 = new TestWallet(
    mvc.PrivateKey.fromWIF(key6),
    new DummyProvider()
)
export const wallet7 = new TestWallet(
    mvc.PrivateKey.fromWIF(key7),
    new DummyProvider()
)

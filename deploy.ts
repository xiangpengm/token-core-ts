import * as dotenv from 'dotenv'
import { genContract } from './deployments/Common'

// Load the .env file
dotenv.config()

async function main() {
    const TokenGenesis = genContract('token/tokenGenesis')
    const genesis = new TokenGenesis()
    console.log(genesis)
}

main()

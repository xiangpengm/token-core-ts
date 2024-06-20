import * as fs from 'fs'
import * as path from 'path'

interface JsonObject {
    [key: string]: any
}

function loadJsonFromFile(file: string): JsonObject {
    const data = fs.readFileSync(file, 'utf-8')
    return JSON.parse(data)
}

function saveJsonToFile(file: string, data: JsonObject): void {
    fs.writeFileSync(file, JSON.stringify(data, null, 2))
}

function main(): void {
    const source: string = __dirname + '/source.txt'
    const target: string = __dirname + '/target.txt'
    const sourceFileList: string[] = fs
        .readFileSync(source, 'utf-8')
        .split('\n')
        .filter(Boolean)
    const targetFileList: string[] = fs
        .readFileSync(target, 'utf-8')
        .split('\n')
        .filter(Boolean)

    for (let i = 0; i < sourceFileList.length; i++) {
        const sourceJsonFile: string = path.join(__dirname, sourceFileList[i])
        const targetJsonFile: string = path.join(__dirname, targetFileList[i])
        const sourceJson: JsonObject = loadJsonFromFile(sourceJsonFile)
        const targetJson: JsonObject = loadJsonFromFile(targetJsonFile)
        targetJson['hex'] = sourceJson['hex']
        saveJsonToFile(targetJsonFile, targetJson)
    }
}

main()

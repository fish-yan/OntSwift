import Testing
import Foundation
import CryptoSwift
import CryptoKit
import BigInt
import Web3Tool
@testable import OntSwift

let mnemonic = "bone swamp olympic slender ignore error hour orient cricket night direct answer"
let seed = "0x2679a62e3b60a751f5bce6938196a703ca52cd29ff9f93fa7d516e522eacad9f"
let privateKeyHex = "5bdf1bad98fc167ed1e09cb5b13fa5bd104da1e7797719d1482af552bea55248"
let publicKeyHex = "03342cfedea6cab6956750c112f47c9be659d618c23c045fde644cb6336d5d3803"
let base58Address = "AcXGTpdGSTgWUoZa4p5vpjNYjSzfZHAjcW"
let wif = "KzJJBi5KNzjxAczbtvJqxLDdrK8RXHBg8grxYf3DDKAod9svN5vV"

@Test func ethTest() async throws {
    let seed = BIP39.seedFromMmemonics(mnemonic.components(separatedBy: " "))!
    print(seed.toHexString())
    let hdNode = HDNode(seed: seed)
    let node = hdNode?.derive(path: "m/44'/60'/0'/0/0")
    let prv = node!.privateKey!
    let pub = node!.publicKey
    print(prv.toHexString())
    print(pub.toHexString())
}

@Test func accountWithMnemonic() async throws {
    let account = try Account(mnemonic: mnemonic)
    #expect(account.privateKey.data.toHexString() == privateKeyHex)
    #expect(account.publicKey.data.toHexString() == publicKeyHex)
    #expect(account.address.base58 == base58Address)
}

@Test func accountWithPrivateKey() async throws {
    let account = try Account(privateKey: Data(hex: privateKeyHex))
    #expect(account.privateKey.data.toHexString() == privateKeyHex)
    #expect(account.publicKey.data.toHexString() == publicKeyHex)
    #expect(account.address.base58 == base58Address)
}

@Test func privateKeyToWif() async throws {
    let privateKey = try PrivateKey(data: Data(hex: privateKeyHex))
    #expect(privateKey.wif == wif)
}

@Test func wifToPrivateKey() async throws {
    let privateKey = try PrivateKey(wif: wif)
    #expect(privateKey.data.toHexString() == privateKeyHex)
}

@Test func verifyPrivateKey() async throws {
    let privateKey = try PrivateKey(data: Data(hex: privateKeyHex))
    let publicKey = try PublicKey(privateKey: privateKey.data)
    let address = Address(publicKey: publicKey.data)
    #expect(address.base58 == base58Address)
}

@Test func verifyAddress() async throws {
    let address = try Address(base58: base58Address)
    #expect(address.base58 == base58Address)
}

@Test func signature() async throws {
    let signer = DefaultSigner(privateKey: Data(hex: privateKeyHex))
    let signature = try signer.sign(Data(hex: "9ff6f4ca1b4c95896e2c561bfbe6551cb1c12096c856786c5e784bd979aa0947818aeed48ea2f816553b83cb6e478d0afa79cabc2bad4f7ce5e50b5cf0de93c601"))
    print(signature.data.toHexString())
    #expect(signature.data.toHexString() == "f1a204d92b5b508776fabefb57b35392de11c1949bccc9b85bbf9c47414f04cf71230870952321af7a3438a2584137307f3dbdd86f154d258dc854b78c97e21e01")
}

@Test func testK() {
    let k = RFC6979.generateK(privateKey: Data(hex: privateKeyHex), message: "sample".data(using: .utf8)!.sha256())
    print(String(k, radix: 16))
}

@Test func nativeONTTransfer() async throws {
    let account = try Account(privateKey: Data(hex: privateKeyHex))
    let request = NativeTransferRequest(
        token: .ont,
        from: account.address,
        to: account.address,
        amount: BigUInt(1),
        gas: GasConfig(gasPrice: 500, gasLimit: 20000),
        nonce: 1
    )
    let transaction = try account.signNativeTransfer(request)
    #expect(try transaction.serializeUnsigned().toHexString() == "00d101000000f401000000000000204e000000000000e39772a37b56e1964caf6a34e3d6091bc58795fd7100c66b14e39772a37b56e1964caf6a34e3d6091bc58795fd6a7cc814e39772a37b56e1964caf6a34e3d6091bc58795fd6a7cc8516a7cc86c51c1087472616e736665721400000000000000000000000000000000000000010068164f6e746f6c6f67792e4e61746976652e496e766f6b6500")
    #expect(try transaction.serialize().toHexString() == "00d101000000f401000000000000204e000000000000e39772a37b56e1964caf6a34e3d6091bc58795fd7100c66b14e39772a37b56e1964caf6a34e3d6091bc58795fd6a7cc814e39772a37b56e1964caf6a34e3d6091bc58795fd6a7cc8516a7cc86c51c1087472616e736665721400000000000000000000000000000000000000010068164f6e746f6c6f67792e4e61746976652e496e766f6b65000141406f825ed004609f8df917922e2d11aa087db19df91a9470b04fc1e8b9fe604e7e932a1848c4344dffa880c91e9be6f342175233914965ac97bcf2f6c08876e015232103342cfedea6cab6956750c112f47c9be659d618c23c045fde644cb6336d5d3803ac")
}

@Test func nativeONGTransfer() async throws {
    let account = try Account(privateKey: Data(hex: privateKeyHex))
    
    let request = try NativeTransferRequest(
        token: .ong,
        from: account.address.base58,
        to: account.address.base58,
        amount: "1",
        gas: GasConfig(gasPrice: 500, gasLimit: 20000),
        nonce: 1
    )
    let transaction = try request.makeTransaction()
    #expect(try transaction.serializeUnsigned().toHexString() == "00d101000000f401000000000000204e000000000000e39772a37b56e1964caf6a34e3d6091bc58795fd8100c66b14e39772a37b56e1964caf6a34e3d6091bc58795fd6a7cc814e39772a37b56e1964caf6a34e3d6091bc58795fd6a7cc81000ca9a3b0000000000000000000000006a7cc86c51c1087472616e736665721400000000000000000000000000000000000000020068164f6e746f6c6f67792e4e61746976652e496e766f6b6500")
    
    let baseUnitRequest = NativeTransferRequest(
        token: .ong,
        from: account.address,
        to: account.address,
        amount: BigUInt(1_000_000_000),
        gas: GasConfig(gasPrice: 500, gasLimit: 20000),
        nonce: 1
    )
    let signed = try account.signNativeTransfer(baseUnitRequest)
    let signedUnsigned = try signed.serializeUnsigned().toHexString()
    let builderUnsigned = try transaction.serializeUnsigned().toHexString()
    #expect(signedUnsigned == builderUnsigned)
    
    let decimalRequest = try NativeTransferRequest(
        token: .ong,
        from: account.address.base58,
        to: account.address.base58,
        amount: "1",
        gas: GasConfig(gasPrice: 500, gasLimit: 20000),
        nonce: 1
    )
    let signedFromDecimal = try account.signNativeTransfer(decimalRequest)
    #expect(try signedFromDecimal.serializeUnsigned().toHexString() == builderUnsigned)
}

@Test func sendRawTransactionBuildsJSONRPCRequest() async throws {
    let client = OntRPCClient(endpointURL: URL(string: "https://polaris1.ont.io:10339")!)
    let request = try client.makeURLRequest(
        for: .sendRawTransaction(hexTx: "00d1", preExec: true),
        requestID: .int(3)
    )
    
    #expect(request.httpMethod == "POST")
    #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
    #expect(request.value(forHTTPHeaderField: "Accept") == "application/json")
    
    let body = try JSONDecoder().decode(OntRPCRequest.self, from: request.httpBody!)
    #expect(body.jsonrpc == "2.0")
    #expect(body.method == "sendrawtransaction")
    #expect(body.params == [.string("00d1"), .int(1)])
    #expect(body.id == .int(3))
}

@Test func sendRawTransactionDecodesStringResult() async throws {
    let client = OntRPCClient(endpointURL: URL(string: "https://polaris1.ont.io:10339")!)
    let data = """
    {"jsonrpc":"2.0","id":3,"result":"tx-hash"}
    """.data(using: .utf8)!
    
    let result: String = try client.decodeResponse(data)
    #expect(result == "tx-hash")
}

@Test func sendRawTransactionDecodesRPCError() async throws {
    let client = OntRPCClient(endpointURL: URL(string: "https://polaris1.ont.io:10339")!)
    let data = """
    {"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Invalid params"}}
    """.data(using: .utf8)!
    
    do {
        let _: String = try client.decodeResponse(data)
        Issue.record("Expected RPC error")
    } catch let OntRPCError.rpc(error) {
        #expect(error.code == -32602)
        #expect(error.message == "Invalid params")
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}

@Test func rpcMethodsBuildExpectedNamesAndParams() async throws {
    let cases: [(OntRPCMethod, String, [OntRPCValue])] = [
        (.getBlockCount, "getblockcount", []),
        (.getBlockHash(height: 12), "getblockhash", [.int(12)]),
        (.getBlockByHeight(height: 12, verbose: true), "getblock", [.int(12), .int(1)]),
        (.getBlockByHash(hash: "block-hash", verbose: false), "getblock", [.string("block-hash"), .int(0)]),
        (.getRawTransaction(txHash: "tx-hash", verbose: true), "getrawtransaction", [.string("tx-hash"), .int(1)]),
        (.getBalance(address: base58Address), "getbalance", [.string(base58Address)]),
        (.getGasPrice, "getgasprice", []),
        (.getSmartCodeEvent(txHash: "tx-hash"), "getsmartcodeevent", [.string("tx-hash")]),
        (.getNetworkID, "getnetworkid", [])
    ]
    
    for (method, name, params) in cases {
        #expect(method.name == name)
        #expect(method.params == params)
    }
}

@Test func rpcDecodesCommonTypedResults() async throws {
    let client = OntRPCClient(endpointURL: URL(string: "https://polaris1.ont.io:10339")!)
    
    let blockCountData = """
    {"jsonrpc":"2.0","id":3,"result":100}
    """.data(using: .utf8)!
    let blockCount: Int = try client.decodeResponse(blockCountData)
    #expect(blockCount == 100)
    
    let balanceData = """
    {"jsonrpc":"2.0","id":3,"result":{"ont":"10","ong":"2000000000"}}
    """.data(using: .utf8)!
    let balance: OntBalance = try client.decodeResponse(balanceData)
    #expect(balance == OntBalance(ont: "10", ong: "2000000000"))
    
    let gasPriceData = """
    {"jsonrpc":"2.0","id":3,"result":{"gasprice":500,"height":1234}}
    """.data(using: .utf8)!
    let gasPrice: OntGasPrice = try client.decodeResponse(gasPriceData)
    #expect(gasPrice == OntGasPrice(gasprice: .int(500), height: .int(1234)))
    
    let networkIDData = """
    {"jsonrpc":"2.0","id":3,"result":1}
    """.data(using: .utf8)!
    let networkID: OntRPCValue = try client.decodeResponse(networkIDData)
    #expect(networkID == .int(1))
}

@Test func buildAndSendONTTransferTransaction() async throws {
    guard let context = try liveRPCContext() else { return }
    
    let request = NativeTransferRequest(
        token: .ont,
        from: context.account.address,
        to: context.toAddress,
        amount: BigUInt(1),
        gas: context.gas,
        nonce: Transaction.randomNonce()
    )
    let transaction = try context.account.signNativeTransfer(request)
    let txHash = try await context.client.sendRawTransaction(transaction)
    
    #expect(!txHash.isEmpty)
}

@Test func buildAndSendONGTransferTransaction() async throws {
    guard let context = try liveRPCContext() else { return }
    
    let request = NativeTransferRequest(
        token: .ong,
        from: context.account.address,
        to: context.toAddress,
        amount: BigUInt(1),
        gas: context.gas,
        nonce: Transaction.randomNonce()
    )
    let transaction = try context.account.signNativeTransfer(request)
    let txHash = try await context.client.sendRawTransaction(transaction)
    
    #expect(!txHash.isEmpty)
}

private struct LiveRPCContext {
    let client: OntRPCClient
    let account: Account
    let toAddress: Address
    let gas: GasConfig
}

private func liveRPCContext() throws -> LiveRPCContext? {
    let environment = ProcessInfo.processInfo.environment
    guard environment["ONT_INTEGRATION_BROADCAST"] == "1",
          let rpcURL = environment["ONT_INTEGRATION_RPC_URL"],
          let privateKeyHex = environment["ONT_INTEGRATION_PRIVATE_KEY"] else {
        return nil
    }
    
    let account = try Account(privateKey: Data(hex: privateKeyHex))
    let toAddress: Address
    if let rawToAddress = environment["ONT_INTEGRATION_TO_ADDRESS"] {
        toAddress = try Address(base58: rawToAddress)
    } else {
        toAddress = account.address
    }
    
    let gasPrice = environment["ONT_INTEGRATION_GAS_PRICE"].flatMap(UInt64.init) ?? 500
    let gasLimit = environment["ONT_INTEGRATION_GAS_LIMIT"].flatMap(UInt64.init) ?? 20_000
    
    return try LiveRPCContext(
        client: OntRPCClient(rpcURL: rpcURL),
        account: account,
        toAddress: toAddress,
        gas: GasConfig(gasPrice: gasPrice, gasLimit: gasLimit)
    )
}

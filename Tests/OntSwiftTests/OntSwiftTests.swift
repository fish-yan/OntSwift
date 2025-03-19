import Testing
import Foundation
import CryptoSwift
import CryptoKit
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
    let privateKey = try PrivateKey(data: Data(hex: privateKeyHex))
    let messageData = "123456789".data(using: .utf8)!
    print(messageData.toHexString())
    let signer = DefaultSigner(privateKey: privateKey)
    let signature = try signer.sign(messageData)
    print(signature.toHexString())
}

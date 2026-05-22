//
//  Account.swift
//  OntSwift
//
//  Created by yan on 11/3/25.
//

import Foundation
import Bip39
import HDNode

public class Account {
    private static let path = "m/44'/1024'/0'/0/0"
    public let privateKey: PrivateKey
    public let publicKey: PublicKey
    public let address: Address
    
    public init(privateKey: Data) throws {
        self.privateKey = try PrivateKey(data: privateKey)
        publicKey = try PublicKey(privateKey: privateKey)
        address = Address(publicKey: publicKey.data)
    }
    
    public convenience init(mnemonic: String) throws {
        guard let seed = BIP39.seedFromMmemonics(mnemonic),
              let masterNode = HDNode(seed: seed, seedType: .nist256p1),
              let node = masterNode.derive(path: Account.path),
              let privateKey = node.privateKey else {
            throw AccountError.invalidData
        }
        try self.init(privateKey: privateKey)
    }
    
    public func signNativeTransfer(_ request: NativeTransferRequest) throws -> Transaction {
        guard request.from.data == address.data else {
            throw AccountError.addressMismatch
        }
        let transaction = try request.makeTransaction()
        try transaction.sign(with: self)
        return transaction
    }
}

public enum AccountError: Error {
    case invalidData
    case deriveFailed
    case addressMismatch
}

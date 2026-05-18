//
//  Account.swift
//  OntSwift
//
//  Created by yan on 11/3/25.
//

import Foundation
import Bip39
import HDNode
import BigInt

public class Account {
    private static let path = "m/44'/1024'/0'/0/0"
    public let privateKey: PrivateKey
    public let publicKey: PublicKey
    public let address: Address
    
    init(privateKey: Data) throws {
        self.privateKey = try PrivateKey(data: privateKey)
        publicKey = try PublicKey(privateKey: privateKey)
        address = Address(publicKey: publicKey.data)
    }
    
    convenience init(mnemonic: String) throws {
        guard let seed = BIP39.seedFromMmemonics(mnemonic),
              let masterNode = HDNode(seed: seed, seedType: .nist256p1),
              let node = masterNode.derive(path: Account.path),
              let privateKey = node.privateKey else {
            throw AccountError.invalidData
        }
        try self.init(privateKey: privateKey)
    }
    
    func sendNative(to: Address, amount: BigUInt, gasPrice: BigUInt = 0, gasLimit: BigUInt = 20000) {
        let structure = Struct()
        structure.add(params: address, to, amount)
        let list = [[structure]]
        let transaction = Transaction()
        transaction.from = address
        transaction.to = to
    }
    
}

enum AccountError: Error {
    case invalidData
    case deriveFailed
}


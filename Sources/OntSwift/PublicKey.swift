//
//  PublicKey.swift
//  OntSwift
//
//  Created by yan on 14/3/25.
//

import Foundation
import CryptoKit

public struct PublicKey {
    public let data: Data
    
    public init(data: Data) {
        self.data = data
    }
    
    public init(privateKey: Data) throws {
        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: privateKey.bytes)
        let publicKey = privateKey.publicKey.compressedRepresentation
        self.init(data: publicKey)
    }
    
    public func serialize() throws -> Data {
        try ScriptBuilder()
            .push(data: data)
            .push(opcode: Opcode.CHECKSIG)
            .buf
    }
}

enum PublicKeyError: Error {
    case invalidData
}

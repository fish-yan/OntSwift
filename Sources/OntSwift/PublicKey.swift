//
//  PublicKey.swift
//  OntSwift
//
//  Created by yan on 14/3/25.
//

import Foundation
import CryptoKit

public struct PublicKey {
    let data: Data
    
    init(data: Data) {
        self.data = data
    }
    
    init(privateKey: Data) throws {
        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: privateKey.bytes)
        let publicKey = privateKey.publicKey.compressedRepresentation
        self.init(data: publicKey)
    }
    
    func serialize() throws -> Data {
        try ScriptBuilder()
            .push(varbytes: data)
            .push(opcode: Opcode.CHECKSIG)
            .buf
    }
}

enum PublicKeyError: Error {
    case invalidData
}

//
//  PrivateKey.swift
//  OntSwift
//
//  Created by yan on 17/3/25.
//

import Foundation
import Base58
import CryptoKit

public struct PrivateKey {
    private static let version: UInt8 = 0x80
    private static let compressed: UInt8 = 0x01
    
    let data: Data
    let wif: String
    
    init(data: Data) throws {
        _ = try P256.Signing.PrivateKey(rawRepresentation: data.bytes)
        self.data = data
        let wifData = Data() + PrivateKey.version + data + PrivateKey.compressed
        wif = wifData.bytes.base58CheckEncodedString
    }
    
    init(wif: String) throws {
        guard let data = wif.base58CheckDecodedData,
        data.count == 34 else {
            throw PrivateKeyError.invalidWIF
        }
        let version = data.first
        let compressed = data.last
        guard version == PrivateKey.version && compressed == PrivateKey.compressed else {
            throw PrivateKeyError.invalidWIF
        }
        try self.init(data: data[1..<33])
    }
    
}

enum PrivateKeyError: Error {
    case invalidWIF
}

//
//  Address.swift
//  OntSwift
//
//  Created by yan on 11/3/25.
//

import Foundation
import Base58
import RIPEMD160

public struct Address {
    private static let coinVersion: UInt8 = 0x17
    
    public let data: Data
    
    public let base58: String
    
    public init(_ data: Data) {
        self.data = data
        let data = Data() + Address.coinVersion + self.data
        base58 = data.bytes.base58CheckEncodedString
    }
    
    public init(base58: String) throws {
        guard let data = base58.base58CheckDecodedData else {
            throw AddressError.decodeBase58Err
        }
        let version = data[0]
        if version != Address.coinVersion {
            throw AddressError.invalidValue
        }
        self.init(data.subdata(in: 1..<21))
    }
    
    public init(publicKey: Data) {
        let data = Data() + Opcode.push(publicKey) + Opcode.CHECKSIG
        let hash = data.sha256().ripemd160()
        self.init(hash)
    }
}

public enum AddressError: Error {
  case invalidValue, decodeBase58Err
}

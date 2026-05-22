//
//  Transaction.swift
//  OntSwift
//
//  Created by yan on 1/4/25.
//

import Foundation

public enum TransactionType: UInt8 {
  case bookKeeper = 0x02
  case claim = 0x03
  case deploy = 0xD0
  case invoke = 0xD1
  case enrollment = 0x04
  case vote = 0x05

  public var name: String {
    switch self {
    case .bookKeeper: return "BookKeeper"
    case .claim: return "Claim"
    case .deploy: return "Deploy"
    case .invoke: return "Invoke"
    case .enrollment: return "Enrollment"
    case .vote: return "Vote"
    }
  }
}


public class Transaction {
    public internal(set) var version: UInt8
    public internal(set) var type: TransactionType
    public internal(set) var nonce: UInt32
    public internal(set) var gasPrice: UInt64
    public internal(set) var gasLimit: UInt64
    public internal(set) var payer: Address?
    public internal(set) var from: Address?
    public internal(set) var to: Address?
    public internal(set) var signatures: [TxSignature]
    public internal(set) var payload: Payload?
    
    public init(
        type: TransactionType = .invoke,
        nonce: UInt32 = Transaction.randomNonce(),
        gasPrice: UInt64 = 0,
        gasLimit: UInt64 = 0,
        payer: Address? = nil,
        payload: Payload? = nil
    ) {
        self.version = 0
        self.type = type
        self.nonce = nonce
        self.gasPrice = gasPrice
        self.gasLimit = gasLimit
        self.payer = payer
        self.signatures = []
        self.payload = payload
    }
    
    public static func randomNonce() -> UInt32 {
        UInt32.random(in: 0..<UInt32(Int32.max))
    }
    
    public func serializeUnsigned() throws -> Data {
        guard let payload else {
            throw TransactionError.missingPayload
        }
        guard let payer = payer ?? from else {
            throw TransactionError.missingPayer
        }
        
        let builder = try ScriptBuilder()
            .append(littleEndian: version)
            .append(littleEndian: type.rawValue)
            .append(littleEndian: nonce)
            .append(littleEndian: gasPrice)
            .append(littleEndian: gasLimit)
            .push(rawbytes: payer.data)
            .push(varbytes: payload.serialize())
            .push(varint: 0)
        return builder.buf
    }
    
    public func serialize() throws -> Data {
        let builder = try ScriptBuilder()
            .push(rawbytes: serializeUnsigned())
            .push(varint: UInt64(signatures.count))
        if !signatures.isEmpty {
            for signature in signatures {
                try builder.push(rawbytes: signature.serialize())
            }
        }
        return builder.buf
    }
    
    public func signHash() throws -> Data {
        try serializeUnsigned().sha256().sha256()
    }
    
    public func hash() throws -> Data {
        Data(try signHash().reversed())
    }
    
    public func add(signature: TxSignature) {
        signatures.append(signature)
    }
    
    public func sign(with account: Account) throws {
        let signature = try DefaultSigner(privateKey: account.privateKey.data).signDigest(signHash())
        add(signature: TxSignature(publicKey: account.publicKey, signature: signature))
    }
}

public enum TransactionError: Error {
    case missingPayload
    case missingPayer
}

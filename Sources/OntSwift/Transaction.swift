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


class Transaction {
    var version: UInt8 = 0
    var type: TransactionType = .bookKeeper
    var nonce: UInt32 = 0
    var gasPrice: UInt64 = 0
    var gaslimit: UInt64 = 0
    var payer: Address?
    var from: Address!
    var to: Address!
    var signatures: [TxSignature] = []
    var payload: Payload!
    
    public func serialize() throws -> Data {
        let builder = try ScriptBuilder()
            .push(num: version)
            .push(num: type.rawValue)
            .push(num: nonce)
            .push(num: gasPrice)
            .push(num: gaslimit)
            .push(address: payer ?? from)
            .push(rawbytes: payload.serialize()) // payload
            .push(num: 0)
        if !signatures.isEmpty {
            try builder.push(num: signatures.count)
            for signature in signatures {
                try builder.push(rawbytes: signature.serialize())
            }
        }
        return builder.buf
    }
}

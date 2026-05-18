//
//  TxSignature.swift
//  OntSwift
//
//  Created by yan on 1/4/25.
//

import Foundation

public struct TxSignature {
    public let publicKey: PublicKey
    public let signature: Signature
    
    public init(publicKey: PublicKey, signature: Signature) {
        self.publicKey = publicKey
        self.signature = signature
    }
    
    func serialize() throws -> Data {
        try ScriptBuilder()
            .push(varbytes: signature.data)
            .push(varbytes: publicKey.serialize())
            .buf
    }
}

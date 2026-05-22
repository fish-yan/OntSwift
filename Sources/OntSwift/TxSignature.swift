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
        let signatureProgram = try ScriptBuilder()
            .push(data: signature.rawData)
            .buf
        let publicKeyProgram = try publicKey.serialize()
        return try ScriptBuilder()
            .push(varbytes: signatureProgram)
            .push(varbytes: publicKeyProgram)
            .buf
    }
}

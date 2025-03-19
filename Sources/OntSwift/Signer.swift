//
//  Signer.swift
//  OntSwift
//
//  Created by yan on 18/3/25.
//

import Foundation
import secp256k1

public protocol Signer {
    func sign(_ data: Data) throws -> Data
}

public struct Signature {
    public let v: UInt8
    public let r: Data
    public let s: Data
}

public struct DefaultSigner: Signer {
    private let privateKey: PrivateKey
    public init(privateKey: PrivateKey) {
        self.privateKey = privateKey
    }
    
    public func sign(_ data: Data) throws -> Data {
        let privateKey = try secp256k1.Signing.PrivateKey(dataRepresentation: privateKey.data)
        let signature = try privateKey.signature(for: data)
        return signature.dataRepresentation
//        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: Data(self.privateKey))
//        let signature = try privateKey.signature(for: data)
//        return signature.rawRepresentation
    }
}


extension secp256k1.Signing.PrivateKey {
    func rfc6979Signature<D>(for digest: D) throws -> secp256k1.Signing.ECDSASignature where D : Digest {
        let context = secp256k1.Context.rawRepresentation
        var signature = secp256k1_ecdsa_signature()
        guard secp256k1_ecdsa_sign(
            context,
            &signature,
            Array(digest),
            Array(dataRepresentation),
            secp256k1_nonce_function_rfc6979,
            nil
        ).boolValue else {
            throw secp256k1Error.underlyingCryptoError
        }
        return try secp256k1.Signing.ECDSASignature(dataRepresentation: signature.dataValue)
    }
    
    public func rfc6979Signature<D: DataProtocol>(for data: D) throws -> secp256k1.Signing.ECDSASignature {
        try rfc6979Signature(for: SHA256.hash(data: data))
    }
}

/// An extension for Int32 providing a convenience property.
extension Int32 {
    /// A property that returns a Bool representation of the Int32 value.
    var boolValue: Bool {
        Bool(truncating: NSNumber(value: self))
    }
}

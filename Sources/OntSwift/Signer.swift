//
//  Signer.swift
//  OntSwift
//
//  Created by yan on 18/3/25.
//

import Foundation
import BigInt

public protocol Signer {
    func sign(_ data: Data) throws -> Signature
}

public struct Signature {
    public let r: Data
    public let s: Data
    public let v: UInt8
    
    public init(r: Data, s: Data, v: UInt8 = 1) {
        self.r = r
        self.s = s
        self.v = v
    }
    
    public var data: Data { r + s + v }
    var rawData: Data { r + s }
}

public struct DefaultSigner: Signer {
    private let privateKey: Data
    public init(privateKey: Data) {
        self.privateKey = privateKey
    }
    
    public func sign(_ data: Data) throws -> Signature {
        try signDigest(data.sha256())
    }
    
    public func signDigest(_ data: Data) throws -> Signature {
        let z = BigInt(sign: .plus, magnitude: BigInt.Magnitude(data))

        var r: BigInt = 0
        var s: BigInt = 0
        let d = BigInt(sign: .plus, magnitude: BigInt.Magnitude(privateKey))

        repeat {
            var k = RFC6979.generateK(privateKey: privateKey, message: data)
            k = secp256r1Curve.modN { k } // make sure k belongs to [0, n - 1]

            let point: Curve.Point = secp256r1Curve.G * k
            r = secp256r1Curve.modN { point.x }
            guard !r.isZero else { continue }
            let kInverse = secp256r1Curve.modInverseN(1, k)
            s = secp256r1Curve.modN { kInverse * (z + r * d) }
        } while s.isZero
        return Signature(
            r: r.magnitude.serialize().leftPadded(to: 32),
            s: s.magnitude.serialize().leftPadded(to: 32),
            v: 1
        )
    }
}

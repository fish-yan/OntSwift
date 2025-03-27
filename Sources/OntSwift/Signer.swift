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
    
    var data: Data { r + s + v }
}

public struct DefaultSigner: Signer {
    private let privateKey: Data
    public init(privateKey: Data) {
        self.privateKey = privateKey
    }
    
    public func sign(_ data: Data) throws -> Signature {
        let data = data.sha256()
        let z = BigInt(sign: .plus, magnitude: BigInt.Magnitude(data)) // = message.asData().toNumber()

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
        return Signature(r: r.magnitude.serialize(), s: s.magnitude.serialize(), v: 1)
    }
}

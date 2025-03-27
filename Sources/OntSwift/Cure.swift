//
//  Cure.swift
//  OntSwift
//
//  Created by yan on 21/3/25.
//

import Foundation
import BigInt

struct Curve {
    let P: BigInt
    let a: BigInt
    let b: BigInt
    let G: Curve.Point
    let N: BigInt
    let h: BigInt
}

let secp256r1Curve = Curve(
    P: BigInt("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", radix: 16)!,
    a: BigInt("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", radix: 16)!,
    b: BigInt("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", radix: 16)!,
    G: Curve.Point(
        x: BigInt("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", radix: 16)!,
        y: BigInt("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", radix: 16)!
    ),
    N: BigInt("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", radix: 16)!,
    h: 1
)

extension Curve {
    struct Point {
        public let x: BigInt
        public let y: BigInt

        public init(x: BigInt, y: BigInt) {
            precondition(x >= 0, "Coordinates should have non negative values, x was negative: `\(x)`")
            precondition(y >= 0, "Coordinates should have non negative values, y was negative: `\(y)`")
            self.x = x
            self.y = y
        }
    }
}

extension Curve.Point: Equatable {
    
}

extension Curve.Point {
    static func * (point: Curve.Point, number: BigInt) -> Curve.Point {
        var P: Curve.Point? = point
        let n = number
        var r: Curve.Point!
        for i in 0..<n.magnitude.bitWidth {
            if n.magnitude[bitAt: i] {
                r = addition(r, P)
            }
            P = addition(P, P)
        }
        return r
    }
    
    static func addition(_ p1: Curve.Point?, _ p2: Curve.Point?) -> Curve.Point? {
        guard let p1 = p1 else { return p2 }
        guard let p2 = p2 else { return p1 }

        if p1.x == p2.x && p1.y != p2.y {
            return nil
        }

        if p1 == p2 {
            /// or `p2`, irrelevant since they equal each other
            return doublePoint(p1)
        } else {
            return addPoint(p1, to: p2)
        }
    }
    
    private static func addPoint(_ p1: Curve.Point, to p2: Curve.Point) -> Curve.Point {
        precondition(p1 != p2)
        let λ = secp256r1Curve.modInverseP(p2.y - p1.y, p2.x - p1.x)
        let x3 = secp256r1Curve.modP { λ * λ - p1.x - p2.x }
        let y3 = secp256r1Curve.modP { λ * (p1.x - x3) - p1.y }
        return Curve.Point(x: x3, y: y3)
    }
    
    private static func doublePoint(_ p: Curve.Point) -> Curve.Point {
        let λ = secp256r1Curve.modInverseP(3 * (p.x * p.x) + secp256r1Curve.a, 2 * p.y)

        let x3 = secp256r1Curve.modP { λ * λ - 2 * p.x }
        let y3 = secp256r1Curve.modP { λ * (p.x - x3) - p.y }

        return Curve.Point(x: x3, y: y3)
    }
}

extension Curve {
    var order: BigInt {
        return N
    }
    
    func modP(_ expression: () -> BigInt) -> BigInt {
        return Curve.mod(expression(), modulus: P)
    }

    func modN(_ expression: () -> BigInt) -> BigInt {
        return Curve.mod(expression(), modulus: N)
    }

    func modInverseP(_ v: BigInt, _ w: BigInt) -> BigInt {
        return Curve.modularInverse(v, w, mod: P)
    }

    func modInverseN(_ v: BigInt, _ w: BigInt) -> BigInt {
        return Curve.modularInverse(v, w, mod: N)
    }
}

// math
extension Curve {
    static func mod(_ number: BigInt, modulus: BigInt) -> BigInt {
        var mod = number % modulus
        if mod < 0 {
            mod = mod + modulus
        }
        guard mod >= 0 else { fatalError("NEGATIVE VALUE") }
        return mod
    }
    
    static func modularInverse<T: BinaryInteger>(_ x: T, _ y: T, mod: T) -> T {
        let x = x > 0 ? x : x + mod
        let y = y > 0 ? y : y + mod

        let inverse = extendedEuclideanAlgorithm(z: y, a: mod)

        var result = (inverse * x) % mod

        let zero: T = 0
        if result < zero {
            result = result + mod
        }

        return result
    }
    
    static func extendedEuclideanAlgorithm<T: BinaryInteger>(z: T, a: T) -> T {
        var i = a
        var j = z
        var y1: T = 1
        var y2: T = 0

        let zero: T = 0
        while j > zero {
            let (quotient, remainder) = division(i, j)

            let y = y2 - y1 * quotient

            i = j
            j = remainder
            y2 = y1
            y1 = y
        }

        return y2 % a
    }
    
    static func division<T: BinaryInteger>(_ a: T, _ b: T) -> (quotient: T, remainder: T) {
        return (a / b, a % b)
    }

}

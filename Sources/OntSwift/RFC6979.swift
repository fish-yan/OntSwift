//
//  RFC6979.swift
//  OntSwift
//
//  Created by yan on 21/3/25.
//

import Foundation
import BigInt
import CryptoKit

public class RFC6979 {
    
    /// https://tools.ietf.org/html/rfc6979#section-3.2
    static func generateK(privateKey: Data, message: Data) -> BigInt {

        let byteCount = message.count

        let qlen = secp256r1Curve.order.magnitude.bitWidth

        
        // Step 3.2.a: "h1 = H(m)" - Already performed by the caller
//        let h1: DataConvertible = message
        // Step 3.2.b: "V = 0x01 0x01 0x01 ... 0x01" - (n bytes equal 0x01)
        var V = Data(repeating: 0x01, count: byteCount)
        // Step 3.2.c. "K = 0x00 0x00 0x00 ... 0x00" - (n bytes equal 0x00)
        var K = Data(repeating: 0x00, count: byteCount)

        func HMAC_K(_ data: Data) -> Data {
            var hmac = HMAC<SHA256>(key: SymmetricKey(data: K))
            hmac.update(data: data)
            return Data(hmac.finalize())
        }

        // Step 3.2.d: "K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))"
        K = HMAC_K(V + UInt8(0x00) + privateKey + message)

        // Step 3.2.e: "V = HMAC_K(V)"
        V = HMAC_K(V)

        // Step 3.2.f: "K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))"
        K = HMAC_K(V + UInt8(0x01) + privateKey + message)

        // Step 3.2.g. "V = HMAC_K(V)"
        V = HMAC_K(V)

        func bits2int(_ data: Data) -> BigInt {
            let x = BigInt(sign: .plus, magnitude: BigInt.Magnitude(data))
            let l = x.magnitude.bitWidth
            if l > qlen {
                return x >> (l - qlen)
            }
            return x
        }
        // Step 3.2.h.
        // 3.2.h.1
        var k: BigInt = 0
        repeat { // Note: the probability of not succeeding at the first try is about 2^-127.
            var T = Data()

            // 3.2.h.2
            while T.count < Int(floor(Double((qlen + 7)) / Double(8))) {
                V = HMAC_K(V)
                T = T + V
            }

            // 3.2.h.3
            k = bits2int(T)

            if k > 0 && k < secp256r1Curve.order {
                break
            }

            K = HMAC_K(V + [0])
            V = HMAC_K(V)
        } while true

        return k
    }

}

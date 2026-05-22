//
//  Data+Script.swift
//  OntSwift
//
//  Created by yan on 14/3/25.
//

import Foundation
import BigInt

public protocol BinaryConvertible {
    static func +(lhs: Data, rhs: Self) -> Data
    static func +=(lhs: inout Data, rhs: Self)
}

public extension BinaryConvertible {
    static func +(lhs: Data, rhs: Self) -> Data {
        var value = rhs
        
        let data = withUnsafePointer(to: &value) { pointer in
            Data(buffer: UnsafeBufferPointer(start: pointer, count: 1))
        }
        
        return lhs + data
    }
    
    static func +=(lhs: inout Data, rhs: Self) {
        lhs = lhs + rhs
    }
}

extension UInt8: BinaryConvertible {}
extension UInt16: BinaryConvertible {}
extension UInt32: BinaryConvertible {}
extension UInt64: BinaryConvertible {}
extension Int8: BinaryConvertible {}
extension Int16: BinaryConvertible {}
extension Int32: BinaryConvertible {}
extension Int64: BinaryConvertible {}
extension Int: BinaryConvertible {}

extension Bool: BinaryConvertible {
    public static func +(lhs: Data, rhs: Bool) -> Data {
        return lhs + (rhs ? UInt8(0x01) : UInt8(0x00)).littleEndian
    }
}

extension String: BinaryConvertible {
    public static func +(lhs: Data, rhs: String) -> Data {
        guard let data = rhs.data(using: .ascii) else { return lhs }
        return lhs + data
    }
}

extension Data: BinaryConvertible {
    public static func +(lhs: Data, rhs: Data) -> Data {
        var data = Data()
        data.append(lhs)
        data.append(rhs)
        return data
    }
}

extension Data {
    init<T: FixedWidthInteger>(littleEndian value: T) {
        var value = value.littleEndian
        self = Swift.withUnsafeBytes(of: &value) { Data($0) }
    }
    
    func leftPadded(to count: Int) -> Data {
        guard self.count < count else { return self }
        return Data(repeating: 0, count: count - self.count) + self
    }
    
    func rightPadded(to count: Int) -> Data {
        guard self.count < count else { return self }
        return self + Data(repeating: 0, count: count - self.count)
    }
}

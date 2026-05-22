//
//  Struct.swift
//  OntSwift
//
//  Created by yan on 1/4/25.
//

import Foundation
import BigInt

public enum NativeParameter {
    case bytes(Data)
    case hex(String)
    case bool(Bool)
    case int(Int)
    case uint64(UInt64)
    case address(Address)
    case structure(Struct)
    case structures([Struct])
    case array([NativeParameter])
    case fixedBigUInt(BigUInt, byteCount: Int)
}

public class Struct {
    public private(set) var fields: [NativeParameter] = []
    public var list: [NativeParameter] { fields }
    
    public init() {}
    
    public init(_ fields: NativeParameter...) {
        self.fields = fields
    }
    
    public func add(_ field: NativeParameter) {
        fields.append(field)
    }
    
    public func add(params: NativeParameter...) {
        fields.append(contentsOf: params)
    }
    
    public func add(address: Address) {
        add(.address(address))
    }
    
    public func add(bytes: Data) {
        add(.bytes(bytes))
    }
    
    public func add(hex: String) {
        add(.hex(hex))
    }
    
    public func add(bool: Bool) {
        add(.bool(bool))
    }
    
    public func add(int: Int) {
        add(.int(int))
    }
    
    public func add(uint64: UInt64) {
        add(.uint64(uint64))
    }
    
    public func add(fixedBigUInt value: BigUInt, byteCount: Int) {
        add(.fixedBigUInt(value, byteCount: byteCount))
    }
    
    @available(*, deprecated, message: "Use typed NativeParameter values instead.")
    public func add(params: Any...) throws {
        for param in params {
            fields.append(try NativeParameter(param))
        }
    }
    
    public class RawField {
        public let type: Int
        public let bytes: Data
        
        public init(type: Int, bytes: Data) {
            self.type = type
            self.bytes = bytes
        }
    }
}

extension NativeParameter {
    init(_ value: Any) throws {
        switch value {
        case let value as NativeParameter:
            self = value
        case let value as Data:
            self = .bytes(value)
        case let value as String:
            self = .hex(value)
        case let value as Bool:
            self = .bool(value)
        case let value as Int:
            self = .int(value)
        case let value as UInt64:
            self = .uint64(value)
        case let value as Address:
            self = .address(value)
        case let value as Struct:
            self = .structure(value)
        case let value as [Struct]:
            self = .structures(value)
        case let value as [NativeParameter]:
            self = .array(value)
        default:
            throw NativeBuilderError.unsupportedParamType
        }
    }
}

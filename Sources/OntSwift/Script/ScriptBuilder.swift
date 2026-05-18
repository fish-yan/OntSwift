//
//  ScriptBuilder.swift
//  OntSwift
//
//  Created by yan on 1/4/25.
//

import Foundation
import BigInt

public enum Endian {
    case big, little, native
}

public class ScriptBuilder {
    public internal(set) var buf: Data = Data()
    
    public init() {}
    
    @discardableResult
    public func push(num: some FixedWidthInteger & BinaryConvertible) throws -> Self {
        if num == -1 {
            buf += Opcode.PUSHM1
        } else if num == 0 {
            buf += Opcode.PUSH0
        } else if num > 0 && num < 16 {
            buf += (Opcode.PUSH1 - 1 + UInt8(num))
        } else {
            _ = try push(data: BigInt(num).serialize())
        }
        return self
    }
    
    @discardableResult
    public func push(b: Bool) throws -> Self {
        buf += (b ? Opcode.PUSHT : Opcode.PUSHF)
        return self
    }
    
    @discardableResult
    public func push(rawbytes: Data) -> Self {
        buf.append(rawbytes)
        return self
    }
    
    @discardableResult
    public func push(varint: Int) throws -> Self {
        if varint < 0xFD {
            buf += UInt8(varint)
        } else if varint < 0xFFFF {
            buf += UInt8(0xFD)
            buf += UInt16(varint)
        } else if varint < (0xFFFF_FFFF as UInt) {
            buf += UInt8(0xFE)
            buf += UInt32(varint)
        } else {
            buf += UInt8(0xFF)
            buf += UInt64(varint)
        }
        return self
    }
    
    @discardableResult
    public func push(varbytes: Data) throws -> Self {
        try push(varint: varbytes.count)
        return push(rawbytes: varbytes)
    }
    
    @discardableResult
    public func push(string: String) throws -> Self {
        let data = Data(string.utf8)
        try push(data: data)
        return self
    }
    
    @discardableResult
    public func push(hex: String) throws -> Self {
        let data = Data(hex: hex)
        try push(data: data)
        return self
    }
    
    @discardableResult
    public func push(data: Data) throws -> Self {
        let len = data.count
        if len < Opcode.PUSHBYTES75 {
            buf += UInt8(len)
        } else if len < 0x100 {
            buf += Opcode.PUSHDATA1
            buf += UInt8(len)
        } else if len < 0x10000 {
            buf += Opcode.PUSHDATA2
            buf += UInt16(len)
        } else {
            buf += Opcode.PUSHDATA4
            buf += UInt32(len)
        }
        push(rawbytes: data)
        return self
    }
    
    @discardableResult
    public func push(address: Address) throws -> Self {
        return try push(data: address.data)
    }
    
    @discardableResult
    public func push(opcode: UInt8) throws -> Self {
        buf += opcode
        return self
    }
    
    /*
     public func push(map: [String: AbiParameter]) throws -> Self {
     _ = try push(num: AbiParameter.Typ.map.value())
     _ = try push(num: map.count)
     
     for (key, val) in map {
     _ = try push(num: AbiParameter.Typ.byteArray.value())
     _ = try push(hex: key.data(using: .utf8)!)
     
     switch val.type {
     case .byteArray:
     _ = try push(num: AbiParameter.Typ.byteArray.value())
     guard let val = val.value!.assocValue as? Data else {
     throw ScriptBuilderError.invalidParams
     }
     _ = try push(hex: val)
     case .string:
     _ = try push(num: AbiParameter.Typ.byteArray.value())
     guard let val = val.value!.assocValue as? String else {
     throw ScriptBuilderError.invalidParams
     }
     _ = try push(hex: val.data(using: .utf8)!)
     case .integer:
     _ = try push(num: AbiParameter.Typ.integer.value())
     guard let val = val.value!.assocValue as? Int else {
     throw ScriptBuilderError.invalidParams
     }
     let b = ScriptBuilder()
     _ = try b.push(varint: val)
     _ = try push(hex: b.buf)
     case .long:
     _ = try push(num: AbiParameter.Typ.long.value())
     guard let val = val.value!.assocValue as? BigInt else {
     throw ScriptBuilderError.invalidParams
     }
     let b = ScriptBuilder()
     _ = try b.push(bigint: val)
     _ = try push(hex: b.buf)
     default:
     throw ScriptBuilderError.invalidParams
     }
     }
     return self
     }
     
     public func push(structure: Struct) throws -> Self {
     _ = try push(num: AbiParameter.Typ.structure.value())
     _ = try push(num: structure.list.count)
     for item in structure.list {
     switch item {
     case let item as String:
     _ = try push(num: AbiParameter.Typ.byteArray.value())
     _ = try push(hex: item.data(using: .utf8)!)
     case let item as Int:
     _ = try push(num: AbiParameter.Typ.byteArray.value())
     let b = ScriptBuilder()
     _ = try b.push(varint: item)
     _ = try push(hex: b.buf)
     case let item as Data:
     _ = try push(num: AbiParameter.Typ.byteArray.value())
     _ = try push(hex: item)
     default:
     throw ScriptBuilderError.invalidParams
     }
     }
     return self
     }
     */
}

public enum ScriptBuilderError: Error {
    case invalidIntLen, invalidParams
}

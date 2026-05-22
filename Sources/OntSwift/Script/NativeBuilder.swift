//
//  NativeBuilder.swift
//  OntSwift
//
//  Created by yan on 2/4/25.
//

import Foundation
import BigInt

class NativeBuilder: ScriptBuilder {
    @discardableResult
    public func push(parameter: NativeParameter) throws -> Self {
        switch parameter {
        case let .bytes(data):
            try push(data: data)
        case let .hex(hex):
            try push(hex: hex)
        case let .bool(value):
            try push(b: value)
        case let .int(value):
            try push(num: value)
        case let .uint64(value):
            try push(num: value)
        case let .address(address):
            try push(address: address)
        case let .fixedBigUInt(value, byteCount):
            try push(data: value.littleEndianData(paddedTo: byteCount))
        case let .structure(structure):
            try push(structure: structure)
        case let .structures(structures):
            try push(structures: structures)
        case let .array(parameters):
            try push(parameters: parameters)
                .push(num: parameters.count)
                .push(opcode: Opcode.PACK)
        }
        return self
    }
    
    @discardableResult
    public func push(obj: Any) throws -> Self {
        try push(parameter: NativeParameter(obj))
    }
    
    @discardableResult
    func push(structure: Struct) throws -> Self {
        try structure.fields.forEach {
            try push(parameter: $0)
                .push(opcode: Opcode.DUPFROMALTSTACK)
                .push(opcode: Opcode.SWAP)
                .push(opcode: Opcode.APPEND)
        }
        return self
    }
    
    @discardableResult
    func push(structures: [Struct]) throws -> Self {
        try structures.forEach { try push(structure: $0) }
        return self
    }
    
    @discardableResult
    func push(parameters: [NativeParameter]) throws -> Self {
        for parameter in parameters {
            switch parameter {
            case let .structure(structure):
                try push(num: 0)
                    .push(opcode: Opcode.NEWSTRUCT)
                    .push(opcode: Opcode.TOALTSTACK)
                    .push(structure: structure)
                    .push(opcode: Opcode.FROMALTSTACK)
            case let .structures(structures):
                try push(num: 0)
                    .push(opcode: Opcode.NEWSTRUCT)
                    .push(opcode: Opcode.TOALTSTACK)
                    .push(structures: structures)
                    .push(opcode: Opcode.FROMALTSTACK)
                    .push(num: structures.count)
                    .push(opcode: Opcode.PACK)
            case let .array(parameters):
                try push(parameters: parameters)
                    .push(num: parameters.count)
                    .push(opcode: Opcode.PACK)
            default:
                try push(parameter: parameter)
            }
        }
        return self
    }
}


public enum NativeBuilderError: Error {
  case unsupportedParamType, invalidParams
}

extension BigUInt {
    func littleEndianData(paddedTo count: Int) throws -> Data {
        let bigEndianData = serialize()
        guard bigEndianData.count <= count else {
            throw NativeBuilderError.invalidParams
        }
        return Data(bigEndianData.reversed()).rightPadded(to: count)
    }
}

//
//  NativeBuilder.swift
//  OntSwift
//
//  Created by yan on 2/4/25.
//

import Foundation

class NativeBuilder: ScriptBuilder {
    @discardableResult
    public func push(obj: Any) throws -> Self {
      switch obj {
      case let obj as String:
        try push(hex: obj)
      case let obj as Data:
        try push(data: obj)
      case let obj as Bool:
        try push(b: obj)
      case let obj as Int:
        try push(num: obj)
      case let obj as Address:
        try push(address: obj)
      case let obj as Struct:
        try obj.list.forEach {
          try push(obj: $0)
                .push(opcode: Opcode.DUPFROMALTSTACK)
                .push(opcode: Opcode.SWAP)
                .push(opcode: Opcode.APPEND)
        }
      case let obj as [Struct]:
          try obj.forEach { try push(obj: $0) }
      default:
        throw NativeBuilderError.unsupportedParamType
      }
      return self
    }
    
    @discardableResult
    func push(objs: [Any]) throws -> Self {
        for obj in objs {
            switch obj {
            case let obj as Struct:
                try push(num: 0)
                    .push(opcode: Opcode.NEWSTRUCT)
                    .push(opcode: Opcode.TOALTSTACK)
                    .push(obj: obj)
                    .push(opcode: Opcode.FROMALTSTACK)
            case let obj as [Struct]:
                try push(num: 0)
                    .push(opcode: Opcode.NEWSTRUCT)
                    .push(opcode: Opcode.TOALTSTACK)
                    .push(obj: obj)
                    .push(opcode: Opcode.FROMALTSTACK)
                    .push(num: obj.count)
                    .push(opcode: Opcode.PACK)
            case let obj as [Any]:
                try push(objs: obj)
                    .push(num: obj.count)
                    .push(opcode: Opcode.PACK)
            default:
                try push(obj: obj)
            }
        }
        return self
    }
}


public enum NativeBuilderError: Error {
  case unsupportedParamType, invalidParams
}

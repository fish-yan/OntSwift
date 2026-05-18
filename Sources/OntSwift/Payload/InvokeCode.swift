//
//  InvokeCode.swift
//  OntSwift
//
//  Created by yan on 2/4/25.
//

import Foundation

public struct InvokeCode: Payload {
    var function: String = ""
    var structs: [[Struct]] = []
    var contract: Address!
    private let name = "Ontology.Native.Invoke"
    
    public func serialize() throws -> Data {
        try ScriptBuilder()
            .push(rawbytes: NativeBuilder().push(objs: structs).buf)
            .push(string: function)
            .push(address: contract)
            .push(num: 0)
            .push(opcode: Opcode.SYSCALL)
            .push(string: name)
            .buf
    }
}

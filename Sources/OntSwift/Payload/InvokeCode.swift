//
//  InvokeCode.swift
//  OntSwift
//
//  Created by yan on 2/4/25.
//

import Foundation

public struct InvokeCode: Payload {
    public var function: String
    public var parameters: [NativeParameter]
    public var contract: Address
    private let name = "Ontology.Native.Invoke"
    
    public init(function: String, parameters: [NativeParameter], contract: Address) {
        self.function = function
        self.parameters = parameters
        self.contract = contract
    }
    
    public init(function: String, structs: [[Struct]], contract: Address) {
        self.function = function
        self.parameters = structs.map { .structures($0) }
        self.contract = contract
    }
    
    public func serialize() throws -> Data {
        try ScriptBuilder()
            .push(rawbytes: NativeBuilder().push(parameters: parameters).buf)
            .push(string: function)
            .push(address: contract)
            .push(num: 0)
            .push(opcode: Opcode.SYSCALL)
            .push(string: name)
            .buf
    }
}

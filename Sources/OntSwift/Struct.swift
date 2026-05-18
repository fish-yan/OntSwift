//
//  Struct.swift
//  OntSwift
//
//  Created by yan on 1/4/25.
//

import Foundation

public class Struct {
    public var list: [Any] = []
    
    public init() {}
    
    public func add(params: Any...) {
        for p in params {
            list.append(p)
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

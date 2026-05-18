//
//  Payload.swift
//  OntSwift
//
//  Created by yan on 2/4/25.
//

import Foundation

public protocol Payload {
  func serialize() throws -> Data
//  func deserialize<T>(r: T) throws -> Void where T: ScriptReader
}

//
//  OntRPCClient.swift
//  OntSwift
//
//  Created by Codex on 22/5/26.
//

import Foundation

public final class OntRPCClient {
    public let endpointURL: URL
    private let session: URLSession
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    
    public init(
        endpointURL: URL,
        session: URLSession = .shared,
        encoder: JSONEncoder = JSONEncoder(),
        decoder: JSONDecoder = JSONDecoder()
    ) {
        self.endpointURL = endpointURL
        self.session = session
        self.encoder = encoder
        self.decoder = decoder
    }
    
    public convenience init(rpcURL: String) throws {
        guard let endpointURL = URL(string: rpcURL) else {
            throw OntRPCError.invalidURL(rpcURL)
        }
        self.init(endpointURL: endpointURL)
    }
    
    public func getBlockCount(requestID: OntRPCID = .int(3)) async throws -> Int {
        try await call(.getBlockCount, requestID: requestID)
    }
    
    public func getBlockHash(height: Int, requestID: OntRPCID = .int(3)) async throws -> String {
        try await call(.getBlockHash(height: height), requestID: requestID)
    }
    
    public func getBlock(
        height: Int,
        verbose: Bool = false,
        requestID: OntRPCID = .int(3)
    ) async throws -> OntRPCValue {
        try await call(.getBlockByHeight(height: height, verbose: verbose), requestID: requestID)
    }
    
    public func getBlock(
        hash: String,
        verbose: Bool = false,
        requestID: OntRPCID = .int(3)
    ) async throws -> OntRPCValue {
        try await call(.getBlockByHash(hash: hash, verbose: verbose), requestID: requestID)
    }
    
    public func getRawTransaction(
        txHash: String,
        verbose: Bool = false,
        requestID: OntRPCID = .int(3)
    ) async throws -> OntRPCValue {
        try await call(.getRawTransaction(txHash: txHash, verbose: verbose), requestID: requestID)
    }
    
    public func getBalance(address: String, requestID: OntRPCID = .int(3)) async throws -> OntBalance {
        try await call(.getBalance(address: address), requestID: requestID)
    }
    
    public func getGasPrice(requestID: OntRPCID = .int(3)) async throws -> OntGasPrice {
        try await call(.getGasPrice, requestID: requestID)
    }
    
    public func getSmartCodeEvent(txHash: String, requestID: OntRPCID = .int(3)) async throws -> OntRPCValue {
        try await call(.getSmartCodeEvent(txHash: txHash), requestID: requestID)
    }
    
    public func getNetworkID(requestID: OntRPCID = .int(3)) async throws -> OntRPCValue {
        try await call(.getNetworkID, requestID: requestID)
    }
    
    @discardableResult
    public func sendRawTransaction(
        hexTx: String,
        preExec: Bool = false,
        requestID: OntRPCID = .int(3)
    ) async throws -> String {
        try await call(.sendRawTransaction(hexTx: hexTx, preExec: preExec), requestID: requestID)
    }
    
    @discardableResult
    public func sendRawTransaction(
        _ transaction: Transaction,
        preExec: Bool = false,
        requestID: OntRPCID = .int(3)
    ) async throws -> String {
        try await sendRawTransaction(
            hexTx: try transaction.serialize().ontRPCHexString,
            preExec: preExec,
            requestID: requestID
        )
    }
    
    public func call<Result: Decodable>(
        _ method: OntRPCMethod,
        requestID: OntRPCID = .int(3)
    ) async throws -> Result {
        let request = try makeURLRequest(for: method, requestID: requestID)
        let (data, response) = try await session.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw OntRPCError.invalidHTTPResponse
        }
        guard (200..<300).contains(httpResponse.statusCode) else {
            throw OntRPCError.httpStatus(httpResponse.statusCode, data: data)
        }
        
        return try decodeResponse(data)
    }
    
    func makeURLRequest(
        for method: OntRPCMethod,
        requestID: OntRPCID = .int(3)
    ) throws -> URLRequest {
        var request = URLRequest(url: endpointURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try encoder.encode(
            OntRPCRequest(
                method: method.name,
                params: method.params,
                id: requestID
            )
        )
        return request
    }
    
    func decodeResponse<Result: Decodable>(_ data: Data) throws -> Result {
        let response = try decoder.decode(OntRPCResponse<Result>.self, from: data)
        
        if let error = response.error {
            throw OntRPCError.rpc(error)
        }
        guard response.jsonrpc == "2.0" else {
            throw OntRPCError.invalidJSONRPCVersion(response.jsonrpc)
        }
        guard let result = response.result else {
            throw OntRPCError.missingResult
        }
        return result
    }
}

public enum OntRPCMethod: Equatable {
    case getBlockCount
    case getBlockHash(height: Int)
    case getBlockByHeight(height: Int, verbose: Bool = false)
    case getBlockByHash(hash: String, verbose: Bool = false)
    case getRawTransaction(txHash: String, verbose: Bool = false)
    case getBalance(address: String)
    case getGasPrice
    case getSmartCodeEvent(txHash: String)
    case getNetworkID
    case sendRawTransaction(hexTx: String, preExec: Bool = false)
    
    public var name: String {
        switch self {
        case .getBlockCount:
            return "getblockcount"
        case .getBlockHash:
            return "getblockhash"
        case .getBlockByHeight, .getBlockByHash:
            return "getblock"
        case .getRawTransaction:
            return "getrawtransaction"
        case .getBalance:
            return "getbalance"
        case .getGasPrice:
            return "getgasprice"
        case .getSmartCodeEvent:
            return "getsmartcodeevent"
        case .getNetworkID:
            return "getnetworkid"
        case .sendRawTransaction:
            return "sendrawtransaction"
        }
    }
    
    public var params: [OntRPCValue] {
        switch self {
        case .getBlockCount, .getGasPrice, .getNetworkID:
            return []
        case .getBlockHash(let height):
            return [.int(height)]
        case .getBlockByHeight(let height, let verbose):
            return [.int(height), .int(verbose ? 1 : 0)]
        case .getBlockByHash(let hash, let verbose):
            return [.string(hash), .int(verbose ? 1 : 0)]
        case .getRawTransaction(let txHash, let verbose):
            return [.string(txHash), .int(verbose ? 1 : 0)]
        case .getBalance(let address):
            return [.string(address)]
        case .getSmartCodeEvent(let txHash):
            return [.string(txHash)]
        case .sendRawTransaction(let hexTx, let preExec):
            return [.string(hexTx), .int(preExec ? 1 : 0)]
        }
    }
}

public enum OntRPCID: Codable, Equatable, Sendable {
    case int(Int)
    case string(String)
    case null
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let int = try? container.decode(Int.self) {
            self = .int(int)
        } else {
            self = .string(try container.decode(String.self))
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .int(let int):
            try container.encode(int)
        case .string(let string):
            try container.encode(string)
        case .null:
            try container.encodeNil()
        }
    }
}

public enum OntRPCValue: Codable, Equatable, Sendable {
    case string(String)
    case int(Int)
    case bool(Bool)
    case array([OntRPCValue])
    case object([String: OntRPCValue])
    case null
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let string = try? container.decode(String.self) {
            self = .string(string)
        } else if let int = try? container.decode(Int.self) {
            self = .int(int)
        } else if let bool = try? container.decode(Bool.self) {
            self = .bool(bool)
        } else if let array = try? container.decode([OntRPCValue].self) {
            self = .array(array)
        } else {
            self = .object(try container.decode([String: OntRPCValue].self))
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let string):
            try container.encode(string)
        case .int(let int):
            try container.encode(int)
        case .bool(let bool):
            try container.encode(bool)
        case .array(let array):
            try container.encode(array)
        case .object(let object):
            try container.encode(object)
        case .null:
            try container.encodeNil()
        }
    }
}

public struct OntBalance: Codable, Equatable, Sendable {
    public let ont: String
    public let ong: String
    
    public init(ont: String, ong: String) {
        self.ont = ont
        self.ong = ong
    }
}

public struct OntGasPrice: Codable, Equatable, Sendable {
    public let gasprice: OntRPCValue
    public let height: OntRPCValue?
    
    public init(gasprice: OntRPCValue, height: OntRPCValue? = nil) {
        self.gasprice = gasprice
        self.height = height
    }
}

public struct OntRPCErrorObject: Codable, Equatable, Error, Sendable {
    public let code: Int
    public let message: String
    public let data: OntRPCValue?
    
    public init(code: Int, message: String, data: OntRPCValue? = nil) {
        self.code = code
        self.message = message
        self.data = data
    }
}

public enum OntRPCError: Error, Equatable, Sendable {
    case invalidURL(String)
    case invalidHTTPResponse
    case httpStatus(Int, data: Data)
    case invalidJSONRPCVersion(String)
    case missingResult
    case rpc(OntRPCErrorObject)
}

struct OntRPCRequest: Codable, Equatable {
    let jsonrpc: String
    let method: String
    let params: [OntRPCValue]
    let id: OntRPCID
    
    init(
        method: String,
        params: [OntRPCValue],
        id: OntRPCID,
        jsonrpc: String = "2.0"
    ) {
        self.jsonrpc = jsonrpc
        self.method = method
        self.params = params
        self.id = id
    }
}

struct OntRPCResponse<Result: Decodable>: Decodable {
    let jsonrpc: String
    let result: Result?
    let error: OntRPCErrorObject?
    let id: OntRPCID?
}

private extension Data {
    var ontRPCHexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

//
//  NativeTransfer.swift
//  OntSwift
//
//  Created by Codex on 18/5/26.
//

import Foundation
import BigInt

public struct GasConfig {
    public let gasPrice: UInt64
    public let gasLimit: UInt64
    
    public init(gasPrice: UInt64 = 0, gasLimit: UInt64 = 20_000) {
        self.gasPrice = gasPrice
        self.gasLimit = gasLimit
    }
}

public enum NativeToken {
    case ont
    case ong
    
    public var contract: Address {
        switch self {
        case .ont:
            return Address(Data(hex: Address.ont))
        case .ong:
            return Address(Data(hex: Address.ong))
        }
    }
    
    public func decimals(for method: NativeTransferMethod = .transfer) -> Int {
        switch (self, method) {
        case (.ont, .transfer):
            return 0
        case (.ont, .transferV2):
            return 9
        case (.ong, .transfer):
            return 9
        case (.ong, .transferV2):
            return 18
        }
    }
    
    func amountParameter(_ amount: BigUInt) throws -> NativeParameter {
        switch self {
        case .ont:
            guard let value = UInt64(exactly: amount) else {
                throw NativeTransferError.amountOverflow
            }
            return .uint64(value)
        case .ong:
            return .fixedBigUInt(amount, byteCount: 16)
        }
    }
}

public enum NativeTransferMethod: String {
    case transfer
    case transferV2
}

public struct NativeTransferRequest {
    public let token: NativeToken
    public let method: NativeTransferMethod
    public let from: Address
    public let to: Address
    public let payer: Address?
    public let amount: BigUInt
    public let gas: GasConfig
    public let nonce: UInt32
    
    public init(
        token: NativeToken,
        method: NativeTransferMethod = .transfer,
        from: Address,
        to: Address,
        payer: Address? = nil,
        amount: BigUInt,
        gas: GasConfig = GasConfig(),
        nonce: UInt32 = Transaction.randomNonce()
    ) {
        self.token = token
        self.method = method
        self.from = from
        self.to = to
        self.payer = payer
        self.amount = amount
        self.gas = gas
        self.nonce = nonce
    }
    
    public init(
        token: NativeToken,
        method: NativeTransferMethod = .transfer,
        from: String,
        to: String,
        payer: String? = nil,
        amount: String,
        gas: GasConfig = GasConfig(),
        nonce: UInt32 = Transaction.randomNonce()
    ) throws {
        guard let fromAddress = try? Address(base58: from),
              let toAddress = try? Address(base58: to) else {
            throw NativeTransferError.invalidAddress
        }
        
        let payerAddress: Address?
        if let payer {
            guard let address = try? Address(base58: payer) else {
                throw NativeTransferError.invalidAddress
            }
            payerAddress = address
        } else {
            payerAddress = nil
        }
        
        try self.init(
            token: token,
            method: method,
            from: fromAddress,
            to: toAddress,
            payer: payerAddress,
            amount: Self.parseAmount(amount, token: token, method: method),
            gas: gas,
            nonce: nonce
        )
    }
    
    public func makePayload() throws -> InvokeCode {
        let transfer = Struct(
            .address(from),
            .address(to),
            try token.amountParameter(amount)
        )
        return InvokeCode(
            function: method.rawValue,
            parameters: [.structures([transfer])],
            contract: token.contract
        )
    }
    
    public func makeTransaction() throws -> Transaction {
        let transaction = Transaction(
            type: .invoke,
            nonce: nonce,
            gasPrice: gas.gasPrice,
            gasLimit: gas.gasLimit,
            payer: payer ?? from,
            payload: try makePayload()
        )
        transaction.from = from
        transaction.to = to
        return transaction
    }
    
    public static func parseAmount(
        _ amount: String,
        token: NativeToken,
        method: NativeTransferMethod = .transfer
    ) throws -> BigUInt {
        try parseDecimalAmount(amount, scale: token.decimals(for: method))
    }
    
    private static func parseDecimalAmount(_ amount: String, scale: Int) throws -> BigUInt {
        let trimmed = amount.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("-") else {
            throw NativeTransferError.invalidAmount
        }
        
        let parts = trimmed.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count <= 2 else {
            throw NativeTransferError.invalidAmount
        }
        
        let whole = String(parts[0])
        let fraction = parts.count == 2 ? String(parts[1]) : ""
        let digitSet = CharacterSet.decimalDigits
        guard (!whole.isEmpty || !fraction.isEmpty),
              whole.unicodeScalars.allSatisfy({ digitSet.contains($0) }),
              fraction.unicodeScalars.allSatisfy({ digitSet.contains($0) }) else {
            throw NativeTransferError.invalidAmount
        }
        
        if fraction.count > scale {
            let extra = fraction.dropFirst(scale)
            guard extra.allSatisfy({ $0 == "0" }) else {
                throw NativeTransferError.invalidAmount
            }
        }
        
        let scaledFraction = String(fraction.prefix(scale)).rightPadded(to: scale, with: "0")
        let scaled = (whole.isEmpty ? "0" : whole) + scaledFraction
        guard let value = BigUInt(scaled, radix: 10) else {
            throw NativeTransferError.invalidAmount
        }
        return value
    }
}

public enum NativeTransferError: Error {
    case invalidAddress
    case invalidAmount
    case amountOverflow
}

extension String {
    func rightPadded(to count: Int, with character: Character) -> String {
        guard self.count < count else { return self }
        return self + String(repeating: String(character), count: count - self.count)
    }
}

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - CryptoSwift Implementation
@_implementationOnly import CryptoSwift
@_implementationOnly import CModExp

final class BigNum {
    private var bigInt: BigUInteger

    init() {
        self.bigInt = .init()
    }

    init?(data: Data) {
        self.bigInt = .init(data)
    }
    
    private init(_ bigInt: BigUInteger) {
        self.bigInt = bigInt
    }
}

extension BigNum {
    static func randomNumber(lessThan limit: BigNum) -> BigNum {
        .init(BigUInteger.randomInteger(lessThan: limit.bigInt))
    }
    
    static func randomNumber(lessThan limit: UInt64) -> BigNum {
        .init(BigUInteger.randomInteger(lessThan: .init(limit)))
    }
}

extension BigNum {
    /// True for an odd prime p > 3 and 1 < self < p - 1. A Diffie-Hellman peer key or
    /// generator of 0, 1 or p - 1 makes the shared secret independent of our private key.
    func isValidDiffieHellmanPeerKey(prime: BigNum) -> Bool {
        prime.bigInt > 3 &&
        prime.bigInt % 2 == 1 &&
        bigInt > 1 &&
        bigInt < prime.bigInt - 1
    }

    var isZero: Bool {
        let isIt = self.bigInt == 0
        
        return isIt
    }

    var bytesCount: Int32 {
        let count = self.bigInt.serialize().count
        
        return .init(count)
    }

    var bitsCount: Int32 {
        let count = self.bigInt.bitWidth

        return .init(count)
    }

    func rand(range: BigNum) -> Bool {
        self.bigInt = CS.BigUInt.randomInteger(lessThan: range.bigInt)
        
        return true
    }

    /// y = g^x mod p. An odd p of at most 512 bytes goes to the C implementation (CryptoSwift
    /// takes many seconds for 2048 bits in a debug build); anything else to CryptoSwift.
    static func modExp(y: BigNum,
                       g: BigNum,
                       x: BigNum,
                       p: BigNum) -> Bool {
        y.bigInt = g.power(exponent: x, modulus: p).bigInt

        return true
    }

    func power(exponent: BigNum, modulus: BigNum) -> BigNum {
        if let result = Self.fastPower(base: bigInt, exponent: exponent.bigInt, modulus: modulus.bigInt) {
            return .init(result)
        }

        let result = bigInt.power(exponent.bigInt,
                                  modulus: modulus.bigInt)

        return .init(result)
    }

    private static func fastPower(base: BigUInteger, exponent: BigUInteger, modulus: BigUInteger) -> BigUInteger? {
        guard modulus > 1, modulus[bitAt: 0] else { return nil }

        let reducedBase = base < modulus ? base : base % modulus
        let modulusBytes = [UInt8](modulus.serialize())
        let baseBytes = [UInt8](reducedBase.serialize())
        let exponentBytes = [UInt8](exponent.serialize())

        guard modulusBytes.count <= Int(RVNC_MODEXP_MAX_BYTES) else { return nil }

        var out = [UInt8](repeating: 0, count: modulusBytes.count)

        let status = rvnc_modexp(baseBytes, baseBytes.count,
                                 exponentBytes, exponentBytes.count,
                                 modulusBytes, modulusBytes.count,
                                 &out)

        guard status == 0 else { return nil }

        return BigUInteger(Data(out))
    }

    func bigEndianData() -> Data? {
        let data = self.bigInt.serialize()
        
        return data
    }
    
    func fixedWidthBigEndianData(length: Int) -> Data? {
        guard length > 0,
              let minimalData = bigEndianData(),
              minimalData.count <= length else {
            return nil
        }

        guard minimalData.count < length else {
            return minimalData
        }

        var paddedData = Data(repeating: 0,
                              count: length - minimalData.count)
        
        paddedData.append(minimalData)

        return paddedData
    }
    
    func isLessThan(_ value: UInt64) -> Bool {
        bigInt < value
    }
}


// MARK: - libtommath Implementation
//@_implementationOnly import libtommath
//
//final class BigNum {
//	private let num: UnsafeMutablePointer<BIGNUM>
//	private let backingDataPointer: UnsafeMutablePointer<UInt8>?
//
//	init() {
//		self.num = BN_new()
//		self.backingDataPointer = nil
//	}
//
//	init?(data: Data) {
//		let dataLength = data.count
//
//		let backingDataPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: dataLength)
//		data.copyBytes(to: backingDataPtr, count: dataLength)
//
//		guard let num = BN_bin2bn(backingDataPtr, .init(dataLength), nil) else {
//			backingDataPtr.deallocate()
//
//			return nil
//		}
//
//		self.num = num
//		self.backingDataPointer = backingDataPtr
//	}
//
//	deinit {
//		backingDataPointer?.deallocate()
//
//		BN_free(num)
//	}
//}
//
//extension BigNum {
//	var isZero: Bool {
//		let isItNum = BN_is_zero(num)
//		let isIt = isItNum != 0
//
//		return isIt
//	}
//
//	var bytesCount: Int32 {
//		let count = BN_num_bytes(num)
//
//		return count
//	}
//
//	var bitsCount: Int32 {
//		let count = BN_num_bits(num)
//
//		return count
//	}
//
//	func rand(range: BigNum) -> Bool {
//		let successNum = BN_rand_range(num, range.num)
//		let success = successNum != 0
//
//		return success
//	}
//
//	static func modExp(y: BigNum,
//					   g: BigNum,
//					   x: BigNum,
//					   p: BigNum) -> Bool {
//		let successNum = BN_mod_exp(y.num,
//									g.num,
//									x.num,
//									p.num)
//
//		let success = successNum != 0
//
//		return success
//	}
//
//	func bigEndianData() -> Data? {
//		let expectedLength = bytesCount
//
//		var data = Data(count: .init(expectedLength))
//
//		let actualLength = data.withUnsafeMutableBytes { dataBufferPtr in
//			guard let dataPtr = dataBufferPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
//				return 0
//			}
//
//			let convertedLength = BN_bn2bin(num, dataPtr)
//
//			return .init(convertedLength)
//		}
//
//		guard actualLength == expectedLength else {
//			return nil
//		}
//
//		return data
//	}
//}

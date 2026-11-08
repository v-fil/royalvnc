#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(CommonCrypto)
import CommonCrypto
#endif

@_implementationOnly import CryptoSwift

/// The primitives of Apple's record layer: AES-128 (one block ECB, and CBC over whole blocks)
/// and SHA-1. Two implementations: CommonCrypto where it exists (hardware AES, fast in debug
/// builds too), CryptoSwift elsewhere. Both are run against the same vectors in the tests.
enum AppleRecordCrypto {
	enum Backend: CaseIterable {
		case commonCrypto
		case cryptoSwift

		/// CommonCrypto where it exists, else CryptoSwift.
		static let preferred: Backend = {
#if canImport(CommonCrypto)
			.commonCrypto
#else
			.cryptoSwift
#endif
		}()

		/// Whether this platform has it.
		var isAvailable: Bool {
			switch self {
				case .commonCrypto:
#if canImport(CommonCrypto)
					return true
#else
					return false
#endif
				case .cryptoSwift:
					return true
			}
		}
	}

	static let blockSize = 16
	static let keySize = 16
	static let digestSize = 20

	/// AES-128-CBC without padding. `data` must be whole blocks; nil if not, or if the key or IV
	/// is not 16 bytes.
	static func cbc(encrypt: Bool,
					key: [UInt8],
					iv: [UInt8],
					data: [UInt8],
					backend: Backend = .preferred) -> [UInt8]? {
		guard key.count == keySize,
			  iv.count == blockSize,
			  data.count.isMultiple(of: blockSize) else {
			return nil
		}

		guard !data.isEmpty else { return [] }

		switch backend {
			case .commonCrypto:
#if canImport(CommonCrypto)
				return commonCryptoCrypt(encrypt: encrypt, options: 0, key: key, iv: iv, data: data)
#else
				return nil
#endif

			case .cryptoSwift:
				do {
					let aes = try AES(key: key, blockMode: CBC(iv: iv), padding: .noPadding)

					return encrypt ? try aes.encrypt(data) : try aes.decrypt(data)
				} catch {
					return nil
				}
		}
	}

	/// AES-128 decryption of one block (ECB).
	static func decryptBlock(_ block: [UInt8],
							 key: [UInt8],
							 backend: Backend = .preferred) -> [UInt8]? {
		guard key.count == keySize,
			  block.count == blockSize else {
			return nil
		}

		switch backend {
			case .commonCrypto:
#if canImport(CommonCrypto)
				return commonCryptoCrypt(encrypt: false,
										 options: CCOptions(kCCOptionECBMode),
										 key: key,
										 iv: nil,
										 data: block)
#else
				return nil
#endif

			case .cryptoSwift:
				do {
					let aes = try AES(key: key, blockMode: ECB(), padding: .noPadding)

					return try aes.decrypt(block)
				} catch {
					return nil
				}
		}
	}

	/// SHA-1 of the 32-bit big-endian `prefix` followed by `data`.
	static func sha1(prefix: UInt32,
					 data: ArraySlice<UInt8>,
					 backend: Backend = .preferred) -> [UInt8] {
		let prefixBytes: [UInt8] = [
			UInt8(truncatingIfNeeded: prefix >> 24),
			UInt8(truncatingIfNeeded: prefix >> 16),
			UInt8(truncatingIfNeeded: prefix >> 8),
			UInt8(truncatingIfNeeded: prefix)
		]

		switch backend {
			case .commonCrypto:
#if canImport(CommonCrypto)
				var context = CC_SHA1_CTX()
				var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))

				CC_SHA1_Init(&context)
				CC_SHA1_Update(&context, prefixBytes, CC_LONG(prefixBytes.count))

				data.withUnsafeBufferPointer { buffer in
					_ = CC_SHA1_Update(&context, buffer.baseAddress, CC_LONG(buffer.count))
				}

				CC_SHA1_Final(&digest, &context)

				return digest
#else
				return []
#endif

			case .cryptoSwift:
				return Digest.sha1(prefixBytes + data)
		}
	}

	/// Whether two byte sequences are equal, in time that depends only on their lengths.
	static func constantTimeEqual(_ lhs: ArraySlice<UInt8>,
								  _ rhs: [UInt8]) -> Bool {
		guard lhs.count == rhs.count else { return false }

		var difference: UInt8 = 0

		for (left, right) in zip(lhs, rhs) {
			difference |= left ^ right
		}

		return difference == 0
	}

#if canImport(CommonCrypto)
	private static func commonCryptoCrypt(encrypt: Bool,
										  options: CCOptions,
										  key: [UInt8],
										  iv: [UInt8]?,
										  data: [UInt8]) -> [UInt8]? {
		var output = [UInt8](repeating: 0, count: data.count)
		var moved = 0

		let status = output.withUnsafeMutableBytes { outputBuffer in
			CCCrypt(CCOperation(encrypt ? kCCEncrypt : kCCDecrypt),
					CCAlgorithm(kCCAlgorithmAES),
					options,
					key, key.count,
					iv,
					data, data.count,
					outputBuffer.baseAddress, outputBuffer.count,
					&moved)
		}

		guard status == CCCryptorStatus(kCCSuccess),
			  moved == data.count else {
			return nil
		}

		return output
	}
#endif
}

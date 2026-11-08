// The record layer's design and tests follow remotex (https://github.com/andrewtheguy/remotex),
// docs/apple-vnc-889.md and src/vnc_record.rs, under this licence:
//
// MIT License
//
// Copyright (c) 2026 Andrew Chen
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Apple Screen Sharing's session encryption (RFB 3.889): the record layer that carries every
/// message in both directions once the server has sent its key. The layout follows the
/// description and tests in remotex's `docs/apple-vnc-889.md` and `src/vnc_record.rs`
/// (MIT, Copyright (c) 2026 Andrew Chen).
///
/// ```text
/// wire       u16 ciphertext_len || ciphertext
/// plaintext  u16 body_len || body || filler || 20-byte trailer
///            filler_len = (-(2 + body_len + 20)) mod 16
/// trailer    SHA1(u32_be(sequence number) || the plaintext before the trailer)
/// ciphertext AES-128-CBC(plaintext)
/// ```
///
/// - One CBC chain per direction for the whole session: a record's last ciphertext block is
///   the next record's IV.
/// - One sequence number per direction, starting at 0, never sent and never reset. A record
///   that is damaged, replayed, dropped or reordered fails its trailer.
/// - A message may span records; the bodies concatenate into the byte stream.
///
/// The key comes in a rekey: a one-rectangle framebuffer update with encoding 1103 whose body
/// is a `u32` generation, then the key and the IV, each one AES-128 block (ECB) encrypted under
/// the wrap key that the login produced. Both directions start from that key and IV.
enum AppleRecordLayer {
	/// The encoding of the rectangle that carries a rekey.
	static let rekeyEncodingType: Int32 = 1103

	/// `u32` generation, wrapped key, wrapped IV.
	static let rekeyLength = 4 + 2 * AppleRecordCrypto.blockSize

	static let bodyLengthSize = 2
	static let trailerSize = AppleRecordCrypto.digestSize

	/// The largest number of whole blocks a `u16` length can give.
	static let maximumRecordLength = (Int(UInt16.max) / AppleRecordCrypto.blockSize) * AppleRecordCrypto.blockSize

	/// The largest body one record carries; longer messages span records.
	static let maximumBodyLength = maximumRecordLength - bodyLengthSize - trailerSize

	/// An empty body with its length, filler and trailer.
	static let minimumRecordLength = recordLength(bodyLength: 0)

	/// The key and IV a rekey installs. Swift arrays can't be reliably wiped, so the keys stay in
	/// memory until that memory is reused.
	struct Keys: Equatable {
		let key: [UInt8]
		let iv: [UInt8]
	}

	/// What a rekey carries.
	struct Rekey: Equatable {
		let generation: UInt32
		let keys: Keys
	}

	/// Filler bytes that round a record's plaintext up to whole blocks.
	static func fillerLength(bodyLength: Int) -> Int {
		let blockSize = AppleRecordCrypto.blockSize
		let unpadded = bodyLengthSize + bodyLength + trailerSize

		return (blockSize - unpadded % blockSize) % blockSize
	}

	/// The ciphertext length of a record with this body.
	static func recordLength(bodyLength: Int) -> Int {
		bodyLengthSize + bodyLength + fillerLength(bodyLength: bodyLength) + trailerSize
	}

	/// Whether a record length off the wire can be a record.
	static func isValidRecordLength(_ length: Int) -> Bool {
		length >= minimumRecordLength &&
		length <= maximumRecordLength &&
		length.isMultiple(of: AppleRecordCrypto.blockSize)
	}

	/// The wrap key of the first rekey after an Apple Diffie-Hellman login (type 30): the MD5
	/// of the shared secret, the key that also encrypted the credentials.
	static func wrapKey(diffieHellmanSharedSecret secret: Data) -> [UInt8] {
		Array(secret.md5Hash())
	}

	/// The generation and keys of a rekey body.
	static func unwrapRekey(_ body: [UInt8],
							wrapKey: [UInt8],
							backend: AppleRecordCrypto.Backend = .preferred) throws -> Rekey {
		let blockSize = AppleRecordCrypto.blockSize

		guard body.count == rekeyLength else {
			throw VNCError.protocol(.appleSessionEncryption(.invalidRekey))
		}

		let generation = UInt32(body[0]) << 24 | UInt32(body[1]) << 16 | UInt32(body[2]) << 8 | UInt32(body[3])

		// Two separate blocks, not chained.
		guard let key = AppleRecordCrypto.decryptBlock(Array(body[4..<(4 + blockSize)]), key: wrapKey, backend: backend),
			  let iv = AppleRecordCrypto.decryptBlock(Array(body[(4 + blockSize)...]), key: wrapKey, backend: backend) else {
			throw VNCError.protocol(.appleSessionEncryption(.cipherFailed))
		}

		return Rekey(generation: generation, keys: Keys(key: key, iv: iv))
	}
}

// MARK: - One Direction
extension AppleRecordLayer {
	/// The cipher state of one direction: key, chaining block and record counter.
	struct Direction {
		let key: [UInt8]
		private(set) var chain: [UInt8]
		private(set) var nextSequenceNumber: UInt32
		private var isExhausted = false
		let backend: AppleRecordCrypto.Backend

		init(keys: Keys,
			 firstSequenceNumber: UInt32 = 0,
			 backend: AppleRecordCrypto.Backend = .preferred) {
			self.key = keys.key
			self.chain = keys.iv
			self.nextSequenceNumber = firstSequenceNumber
			self.backend = backend
		}

		/// Takes the next sequence number. The counter does not wrap around.
		mutating func takeSequenceNumber() throws -> UInt32 {
			guard !isExhausted else {
				throw VNCError.protocol(.appleSessionEncryption(.sequenceNumberExhausted))
			}

			let sequenceNumber = nextSequenceNumber

			if sequenceNumber == .max {
				isExhausted = true
			} else {
				nextSequenceNumber = sequenceNumber + 1
			}

			return sequenceNumber
		}

		mutating func encrypt(_ plaintext: [UInt8]) throws -> [UInt8] {
			guard let ciphertext = AppleRecordCrypto.cbc(encrypt: true, key: key, iv: chain, data: plaintext, backend: backend),
				  ciphertext.count == plaintext.count,
				  ciphertext.count >= AppleRecordCrypto.blockSize else {
				throw VNCError.protocol(.appleSessionEncryption(.cipherFailed))
			}

			chain = Array(ciphertext.suffix(AppleRecordCrypto.blockSize))

			return ciphertext
		}

		mutating func decrypt(_ ciphertext: [UInt8]) throws -> [UInt8] {
			guard ciphertext.count >= AppleRecordCrypto.blockSize,
				  let plaintext = AppleRecordCrypto.cbc(encrypt: false, key: key, iv: chain, data: ciphertext, backend: backend),
				  plaintext.count == ciphertext.count else {
				throw VNCError.protocol(.appleSessionEncryption(.cipherFailed))
			}

			chain = Array(ciphertext.suffix(AppleRecordCrypto.blockSize))

			return plaintext
		}
	}
}

// MARK: - Sealing (client to server)
extension AppleRecordLayer {
	/// Frames outgoing messages into records. Zero filler. One message never shares a record
	/// with the next. Not thread-safe: the caller seals and writes in one order.
	final class Sealer {
		private var direction: Direction
		private var hasFailed = false

		init(direction: Direction) {
			self.direction = direction
		}

		convenience init(keys: Keys) {
			self.init(direction: .init(keys: keys))
		}

		/// The records carrying one whole message: as many full records as needed, then the
		/// rest. An empty message gives one empty record (the connection sends none). After a
		/// failure, every call throws.
		func seal(_ message: [UInt8]) throws -> [UInt8] {
			guard !hasFailed else {
				throw VNCError.protocol(.appleSessionEncryption(.failed))
			}

			do {
				var output = [UInt8]()
				var start = 0

				repeat {
					let end = min(start + maximumBodyLength, message.count)

					output += try sealRecord(message[start..<end])

					start = end
				} while start < message.count

				return output
			} catch {
				hasFailed = true

				throw error
			}
		}

		private func sealRecord(_ body: ArraySlice<UInt8>) throws -> [UInt8] {
			let length = recordLength(bodyLength: body.count)

			var plaintext = [UInt8]()
			plaintext.reserveCapacity(length)

			plaintext.append(UInt8(truncatingIfNeeded: body.count >> 8))
			plaintext.append(UInt8(truncatingIfNeeded: body.count))
			plaintext += body
			plaintext += [UInt8](repeating: 0, count: fillerLength(bodyLength: body.count))

			let sequenceNumber = try direction.takeSequenceNumber()

			plaintext += AppleRecordCrypto.sha1(prefix: sequenceNumber, data: plaintext[...], backend: direction.backend)

			let ciphertext = try direction.encrypt(plaintext)

			return [UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)] + ciphertext
		}
	}
}

// MARK: - Opening (server to client)
extension AppleRecordLayer {
	/// Decrypts and checks incoming records. The trailer is checked first; then the body must fit
	/// in the bytes it covers, and whatever follows the body is filler, of any content and
	/// length (a sender pads to whole blocks; more filler is accepted, as other clients do).
	/// After a failure, every call throws. Not thread-safe.
	final class Opener {
		private var direction: Direction
		private(set) var hasFailed = false

		init(direction: Direction) {
			self.direction = direction
		}

		convenience init(keys: Keys) {
			self.init(direction: .init(keys: keys))
		}

		/// The body of one record, given its ciphertext (the bytes after its length). Nothing
		/// of a record is returned before its trailer is checked.
		func open(_ ciphertext: [UInt8]) throws -> [UInt8] {
			guard !hasFailed else {
				throw VNCError.protocol(.appleSessionEncryption(.failed))
			}

			do {
				return try openRecord(ciphertext)
			} catch {
				hasFailed = true

				throw error
			}
		}

		private func openRecord(_ ciphertext: [UInt8]) throws -> [UInt8] {
			let length = ciphertext.count

			guard isValidRecordLength(length) else {
				throw VNCError.protocol(.appleSessionEncryption(.invalidRecordLength(length: length)))
			}

			let plaintext = try direction.decrypt(ciphertext)
			let sequenceNumber = try direction.takeSequenceNumber()

			let covered = length - trailerSize
			let expected = AppleRecordCrypto.sha1(prefix: sequenceNumber, data: plaintext[0..<covered], backend: direction.backend)

			guard AppleRecordCrypto.constantTimeEqual(plaintext[covered..<length], expected) else {
				throw VNCError.protocol(.appleSessionEncryption(.integrityCheckFailed(sequenceNumber: sequenceNumber)))
			}

			let bodyLength = Int(plaintext[0]) << 8 | Int(plaintext[1])

			guard bodyLengthSize + bodyLength <= covered else {
				throw VNCError.protocol(.appleSessionEncryption(.invalidRecordBody(bodyLength: bodyLength, recordLength: length)))
			}

			return Array(plaintext[bodyLengthSize..<(bodyLengthSize + bodyLength)])
		}
	}
}

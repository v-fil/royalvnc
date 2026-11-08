import Foundation
import XCTest
@testable import RoyalVNCKit

#if canImport(CryptoKit)
import CryptoKit
#endif

// Expected values come from an oracle written from the record layer's description with OpenSSL
// AES and hashlib, not from RoyalVNCKit: Tests/Vectors/apple_record_layer.py prints them
// (AppleRecordLayerVectors.swift). Every vector runs on each crypto backend this platform has.
// Several cases follow remotex's tests (MIT; notice in Sources/RoyalVNCKit/Protocol/AppleRecordLayer.swift).

// MARK: - Sizes
final class AppleRecordLayerSizeTests: XCTestCase {
	func testFillerLengths() {
		// (-(2 + n + 20)) mod 16, written out by hand.
		let cases = [(0, 10), (1, 9), (10, 0), (11, 15), (14, 12), (15, 11), (16, 10), (26, 0), (27, 15), (300, 14), (65498, 0)]

		for (body, filler) in cases {
			XCTAssertEqual(AppleRecordLayer.fillerLength(bodyLength: body), filler, "body \(body)")
			XCTAssertEqual((2 + body + filler + 20) % 16, 0, "body \(body)")
		}
	}

	func testLimits() {
		XCTAssertEqual(AppleRecordLayer.maximumRecordLength, 65520)
		XCTAssertEqual(AppleRecordLayer.maximumBodyLength, 65498)
		XCTAssertEqual(AppleRecordLayer.minimumRecordLength, 32)
		XCTAssertEqual(AppleRecordLayer.recordLength(bodyLength: 65498), 65520)

		for length in [32, 48, 65520] {
			XCTAssertTrue(AppleRecordLayer.isValidRecordLength(length), "\(length)")
		}

		for length in [0, 1, 16, 17, 31, 33, 47, 65521, 65535] {
			XCTAssertFalse(AppleRecordLayer.isValidRecordLength(length), "\(length)")
		}
	}

	func testSetEncryptionMessages() {
		XCTAssertEqual(hex(Array(AppleClientMessage.setEncryptionRequestRekey.data)), "120000010001000100000001")
		XCTAssertEqual(hex(Array(AppleClientMessage.setEncryptionDecryptReceived.data)), "1200000200010000")
	}
}

// MARK: - Comparison
final class AppleRecordCryptoComparisonTests: XCTestCase {
	func testConstantTimeEqual() {
		let value = (0..<20).map { UInt8($0) }

		XCTAssertTrue(AppleRecordCrypto.constantTimeEqual(value[...], value))
		XCTAssertTrue(AppleRecordCrypto.constantTimeEqual([][...], []))

		for index in value.indices {
			var other = value
			other[index] ^= 0x80

			XCTAssertFalse(AppleRecordCrypto.constantTimeEqual(value[...], other), "byte \(index)")
		}

		XCTAssertFalse(AppleRecordCrypto.constantTimeEqual(value[...], Array(value.dropLast())))
		XCTAssertFalse(AppleRecordCrypto.constantTimeEqual(value.dropLast(), value))
		// A slice that does not start at index 0.
		XCTAssertTrue(AppleRecordCrypto.constantTimeEqual(([0xff] + value)[1...], value))
	}
}

// MARK: - Rekey
final class AppleRecordLayerRekeyTests: XCTestCase {
	private let sharedSecret = Data((0..<512).map { UInt8(truncatingIfNeeded: $0 * 7 + 3) })

	func testWrapKeyIsMD5OfSharedSecret() {
#if canImport(CryptoKit)
		XCTAssertEqual(hex(Array(SHA256.hash(data: sharedSecret))), Vectors.sharedSecretSHA256)
#endif

		XCTAssertEqual(hex(AppleRecordLayer.wrapKey(diffieHellmanSharedSecret: sharedSecret)), Vectors.wrapKey)
	}

	func testUnwrap() throws {
		for backend in backends {
			let rekey = try AppleRecordLayer.unwrapRekey(bytes(Vectors.rekey),
														 wrapKey: bytes(Vectors.wrapKey),
														 backend: backend)

			XCTAssertEqual(rekey.generation, 1, "\(backend)")
			XCTAssertEqual(rekey.keys, keys, "\(backend)")
		}
	}

	func testUnwrapDecryptsTheHalvesSeparately() throws {
		// Swapped halves come back swapped, which is only so if each block stands alone.
		let rekey = bytes(Vectors.rekey)
		let swapped = Array(rekey[0..<4] + rekey[20..<36] + rekey[4..<20])

		for backend in backends {
			let unwrapped = try AppleRecordLayer.unwrapRekey(swapped, wrapKey: bytes(Vectors.wrapKey), backend: backend)

			XCTAssertEqual(unwrapped.keys.key, keys.iv, "\(backend)")
			XCTAssertEqual(unwrapped.keys.iv, keys.key, "\(backend)")
		}
	}

	func testUnwrapRefusesOtherLengths() {
		let rekey = bytes(Vectors.rekey)

		for body in [[], Array(rekey.dropLast()), rekey + [0]] {
			assertThrows(.invalidRekey) {
				_ = try AppleRecordLayer.unwrapRekey(body, wrapKey: bytes(Vectors.wrapKey))
			}
		}
	}

	/// Bell, MiscStatus, an empty update, then the rekey.
	private var prelude: [UInt8] {
		[0x02] + [0x14, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02] + [0x00, 0x00, 0x00, 0x00]
	}

	private func rekeyUpdate(rectangles: UInt16 = 1, encoding: Int32 = 1103, body: [UInt8]? = nil) -> [UInt8] {
		let encodingBytes = withUnsafeBytes(of: encoding.bigEndian, Array.init)

		return [0x00, 0x00, UInt8(rectangles >> 8), UInt8(truncatingIfNeeded: rectangles)] +
			[UInt8](repeating: 0, count: 8) + encodingBytes + (body ?? bytes(Vectors.rekey))
	}

	func testReceiveStepsOverBellMiscStatusAndEmptyUpdates() async throws {
		for backend in backends {
			let connection = MemoryConnection(incoming: prelude + rekeyUpdate() + [0xee], chunk: 3)

			let arrival = try await VNCConnection.receiveAppleRekey(connection: connection,
																	wrapKey: bytes(Vectors.wrapKey),
																	backend: backend)

			XCTAssertEqual(arrival.rekey, .init(generation: 1, keys: keys), "\(backend)")
			// The MiscStatus in the prelude is command 2: the pasteboard changed.
			XCTAssertTrue(arrival.isPasteboardChanged, "\(backend)")
			// Not a byte past the rekey is read.
			XCTAssertEqual(connection.remaining, 1, "\(backend)")
		}
	}

	func testReceiveRefusesOtherMessages() async {
		for messageType: UInt8 in [0x01, 0x03, 0x1f, 0x44] {
			let connection = MemoryConnection(incoming: [messageType] + rekeyUpdate())

			await assertThrows(.unexpectedMessageBeforeRekey(messageType: messageType)) {
				_ = try await VNCConnection.receiveAppleRekey(connection: connection, wrapKey: bytes(Vectors.wrapKey))
			}
		}
	}

	func testReceiveRefusesAMalformedRekey() async {
		for update in [rekeyUpdate(rectangles: 2), rekeyUpdate(encoding: 16), rekeyUpdate(encoding: 1011)] {
			let connection = MemoryConnection(incoming: update + [UInt8](repeating: 0, count: 64))

			await assertThrows(.invalidRekey) {
				_ = try await VNCConnection.receiveAppleRekey(connection: connection, wrapKey: bytes(Vectors.wrapKey))
			}
		}
	}

	func testReceiveRefusesALongMiscStatus() async {
		let connection = MemoryConnection(incoming: [0x14, 0x00, 0x04, 0x01] + [UInt8](repeating: 0, count: 1025))

		await assertThrows(.unexpectedMessageBeforeRekey(messageType: 0x14)) {
			_ = try await VNCConnection.receiveAppleRekey(connection: connection, wrapKey: bytes(Vectors.wrapKey))
		}
	}

	func testReceiveFailsOnATruncatedRekey() async {
		let connection = MemoryConnection(incoming: Array(rekeyUpdate().dropLast()))

		do {
			_ = try await VNCConnection.receiveAppleRekey(connection: connection, wrapKey: bytes(Vectors.wrapKey))
			XCTFail("no error")
		} catch { }
	}

	func testARekeyDuringTheSessionEndsIt() async throws {
		let framebuffer = try VNCFramebuffer(logger: VNCPrintLogger(),
											 size: .init(width: 4, height: 4),
											 screens: [],
											 pixelFormat: .init(depth: 24),
											 allocator: nil)

		// FramebufferUpdate after its message type.
		let connection = MemoryConnection(incoming: Array(rekeyUpdate().dropFirst()))

		await assertThrows(.unexpectedRekey) {
			_ = try await VNCProtocol.FramebufferUpdate.receive(connection: connection,
																currentFramebuffer: { framebuffer },
																encodings: [:],
																logger: VNCPrintLogger())
		}
	}
}

// MARK: - Sealing
final class AppleRecordLayerSealerTests: XCTestCase {
	func testRecordsMatchTheOracle() throws {
		let cases = [
			(Vectors.clientMessage0, Vectors.clientRecord0),
			(Vectors.clientMessage1, Vectors.clientRecord1),
			(Vectors.clientMessage2, Vectors.clientRecord2),
			(Vectors.clientMessage3, Vectors.clientRecord3)
		]

		for backend in backends {
			// One sealer: the chain and the counter carry from record to record.
			let sealer = sealer(backend)

			for (index, (message, record)) in cases.enumerated() {
				XCTAssertEqual(hex(try sealer.seal(bytes(message))), record, "\(backend) record \(index)")
			}
		}
	}

	func testAFreshSealerRepeatsOnlyTheFirstRecord() throws {
		for backend in backends {
			XCTAssertEqual(hex(try sealer(backend).seal(bytes(Vectors.clientMessage0))), Vectors.clientRecord0)
			XCTAssertNotEqual(hex(try sealer(backend).seal(bytes(Vectors.clientMessage1))), Vectors.clientRecord1)
		}
	}

	func testALargeMessageSpansRecords() throws {
		let message = (0..<(2 * 65498 + 5)).map { UInt8($0 % 251) }

		for backend in backends {
			let wire = try sealer(backend).seal(message)

			XCTAssertEqual(records(wire).map { $0.count - 2 }, Vectors.largeRecordLengths, "\(backend)")

#if canImport(CryptoKit)
			XCTAssertEqual(hex(Array(SHA256.hash(data: Data(wire)))), Vectors.largeWireSHA256, "\(backend)")
#endif

			// And it reads back as one message.
			let opener = opener(backend)
			let body = try records(wire).flatMap { try opener.open(Array($0.dropFirst(2))) }

			XCTAssertEqual(body, message, "\(backend)")
		}
	}

	func testAMessageOfOneFullRecordStaysOneRecord() throws {
		let wire = try sealer(.preferred).seal([UInt8](repeating: 7, count: 65498))

		XCTAssertEqual(records(wire).count, 1)
		XCTAssertEqual(wire.count, 2 + 65520)
	}

	func testTheSequenceNumberDoesNotWrap() throws {
		for backend in backends {
			let sealer = sealer(backend, firstSequenceNumber: .max)
			let opener = opener(backend, firstSequenceNumber: .max)

			let last = try sealer.seal([1, 2, 3])

			XCTAssertEqual(try opener.open(Array(last.dropFirst(2))), [1, 2, 3])

			assertThrows(.sequenceNumberExhausted) { _ = try sealer.seal([4]) }
			// Failures stay.
			assertThrows(.failed) { _ = try sealer.seal([5]) }
		}
	}
}

// MARK: - Opening
final class AppleRecordLayerOpenerTests: XCTestCase {
	func testRecordsWithRandomFillerMatchTheOracle() throws {
		for backend in backends {
			let opener = opener(backend)
			let bodies = try records(bytes(Vectors.serverStream)).map { try opener.open(Array($0.dropFirst(2))) }

			XCTAssertEqual(bodies.map(hex), [Vectors.serverBody0, Vectors.serverBody1, Vectors.serverBody2, Vectors.serverBody3], "\(backend)")
		}
	}

	func testTheChainCarriesAcrossRecords() {
		// The second record through a direction that never saw the first.
		let second = records(bytes(Vectors.serverStream))[1]

		for backend in backends {
			assertThrows(.integrityCheckFailed(sequenceNumber: 0)) {
				_ = try opener(backend).open(Array(second.dropFirst(2)))
			}
		}
	}

	func testDroppedAndReorderedRecordsFail() throws {
		let all = records(bytes(Vectors.serverStream))

		for backend in backends {
			let dropped = opener(backend)
			_ = try dropped.open(Array(all[0].dropFirst(2)))

			assertThrows(.integrityCheckFailed(sequenceNumber: 1)) { _ = try dropped.open(Array(all[2].dropFirst(2))) }

			let swapped = opener(backend)
			assertThrows(.integrityCheckFailed(sequenceNumber: 0)) { _ = try swapped.open(Array(all[1].dropFirst(2))) }

			let replayed = opener(backend)
			_ = try replayed.open(Array(all[0].dropFirst(2)))

			assertThrows(.integrityCheckFailed(sequenceNumber: 1)) { _ = try replayed.open(Array(all[0].dropFirst(2))) }
		}
	}

	private func openAfterGoodFirst(_ vector: String, backend: AppleRecordCrypto.Backend) throws -> [UInt8] {
		let opener = opener(backend)

		XCTAssertEqual(try opener.open(Array(bytes(Vectors.goodFirstRecord).dropFirst(2))), Array("first".utf8))

		return try opener.open(Array(bytes(vector).dropFirst(2)))
	}

	func testWrongSequenceNumbersFail() {
		for backend in backends {
			// The sender counted record 1 as 0.
			assertThrows(.integrityCheckFailed(sequenceNumber: 1)) { _ = try openAfterGoodFirst(Vectors.replayedSequence, backend: backend) }
			// The sender hashed its counter little-endian.
			assertThrows(.integrityCheckFailed(sequenceNumber: 1)) { _ = try openAfterGoodFirst(Vectors.littleEndianSequence, backend: backend) }
		}
	}

	func testMoreFillerThanNeededIsAccepted() throws {
		for backend in backends {
			// A valid trailer over a 10-byte body and a whole extra block of filler.
			XCTAssertEqual(try openAfterGoodFirst(Vectors.extraFillerBlock, backend: backend), [UInt8](repeating: 0, count: 10), "\(backend)")
		}
	}

	func testABodyLongerThanItsRecordFails() {
		for backend in backends {
			// A valid trailer over a body length larger than the record.
			assertThrows(.invalidRecordBody(bodyLength: 9000, recordLength: 32)) { _ = try openAfterGoodFirst(Vectors.bodyLongerThanRecord, backend: backend) }
		}
	}

	func testABodyOverlappingTheTrailerFails() throws {
		// The largest body a 32-byte record holds is 10 bytes; 11 would reach into the trailer.
		for backend in backends {
			for (bodyLength, accepted) in [(10, true), (11, false)] {
				let direction = AppleRecordLayer.Direction(keys: keys, backend: backend)
				var sealing = direction
				var plaintext = [UInt8(0), UInt8(bodyLength)] + [UInt8](repeating: 0, count: 10)
				plaintext += AppleRecordCrypto.sha1(prefix: try sealing.takeSequenceNumber(), data: plaintext[...], backend: backend)

				let ciphertext = try sealing.encrypt(plaintext)
				let opener = AppleRecordLayer.Opener(direction: direction)

				if accepted {
					XCTAssertEqual(try opener.open(ciphertext).count, bodyLength, "\(backend)")
				} else {
					assertThrows(.invalidRecordBody(bodyLength: bodyLength, recordLength: 32)) { _ = try opener.open(ciphertext) }
				}
			}
		}
	}

	/// An opener that has taken client records 0 and 1, ready for record 2.
	private func openerBeforeClientRecord2(_ backend: AppleRecordCrypto.Backend) throws -> AppleRecordLayer.Opener {
		let opener = opener(backend)

		_ = try opener.open(Array(bytes(Vectors.clientRecord0).dropFirst(2)))
		_ = try opener.open(Array(bytes(Vectors.clientRecord1).dropFirst(2)))

		return opener
	}

	func testAnyChangedCiphertextByteFails() throws {
		let record = Array(bytes(Vectors.clientRecord2).dropFirst(2))

		for backend in backends {
			// Unchanged, it opens.
			XCTAssertEqual(try openerBeforeClientRecord2(backend).open(record), bytes(Vectors.clientMessage2), "\(backend)")

			for index in record.indices {
				var damaged = record
				damaged[index] ^= 0x01

				let opener = try openerBeforeClientRecord2(backend)

				assertThrows(.integrityCheckFailed(sequenceNumber: 2)) { _ = try opener.open(damaged) }
			}
		}
	}

	func testInvalidLengthsFail() {
		for length in [0, 16, 17, 31, 33, 65535] {
			assertThrows(.invalidRecordLength(length: length)) { _ = try opener(.preferred).open([UInt8](repeating: 0, count: length)) }
		}
	}

	func testAFailureIsFinal() throws {
		let all = records(bytes(Vectors.serverStream))
		let opener = opener(.preferred)

		var damaged = Array(all[0].dropFirst(2))
		damaged[5] ^= 0x80

		assertThrows(.integrityCheckFailed(sequenceNumber: 0)) { _ = try opener.open(damaged) }
		// Not even the good record is taken now.
		assertThrows(.failed) { _ = try opener.open(Array(all[0].dropFirst(2))) }
	}
}

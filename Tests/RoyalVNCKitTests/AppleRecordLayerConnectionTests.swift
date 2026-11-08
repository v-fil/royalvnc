import Foundation
import XCTest
@testable import RoyalVNCKit

// The record layer as a connection: reads and writes through AppleRecordLayerNetworkConnection.

// MARK: - The connection
final class AppleRecordLayerConnectionTests: XCTestCase {
	private let serverBodies = [Vectors.serverBody0, Vectors.serverBody1, Vectors.serverBody2, Vectors.serverBody3].flatMap(bytes)

	private func connection(_ base: MemoryConnection) async -> AppleRecordLayerNetworkConnection<MemoryConnection> {
		let connection = AppleRecordLayerNetworkConnection(base: base)
		await connection.startRecordLayer(keys: keys)

		return connection
	}

	private func connection(incoming: [UInt8], chunk: Int = .max) async -> AppleRecordLayerNetworkConnection<MemoryConnection> {
		await connection(MemoryConnection(incoming: incoming, chunk: chunk))
	}

	func testReadsConcatenateBodiesWhateverTheChunks() async throws {
		for chunk in [1, 3, 16, 33, .max] {
			let connection = await connection(incoming: bytes(Vectors.serverStream), chunk: chunk)

			// One byte, then the rest: a read never needs to line up with records.
			let first = try await connection.readUInt8()
			let rest = try await readAll(connection, count: serverBodies.count - 1)

			XCTAssertEqual([first] + rest, serverBodies, "chunk \(chunk)")
			XCTAssertEqual(connection.base.remaining, 0)
		}
	}

	func testBeforeStartingReadsAndWritesAreClear() async throws {
		let connection = AppleRecordLayerNetworkConnection(base: MemoryConnection(incoming: [1, 2, 3]))

		XCTAssertFalse(connection.isRecordLayerActive)

		let clear = try await readAll(connection, count: 3)
		XCTAssertEqual(clear, [1, 2, 3])

		try await connection.write(data: Data([9, 8]))
		XCTAssertEqual(connection.base.written, [9, 8])

		await connection.startRecordLayer(keys: keys)
		XCTAssertTrue(connection.isRecordLayerActive)

		try await connection.write(data: Data(bytes(Vectors.clientMessage0)))
		// An empty write sends nothing.
		try await connection.write(data: Data())
		try await connection.write(data: Data(bytes(Vectors.clientMessage1)))

		XCTAssertEqual(hex(connection.base.written), "0908" + Vectors.clientRecord0 + Vectors.clientRecord1)
	}

	func testABadRecordStopsAllLaterReads() async throws {
		var wire = bytes(Vectors.serverStream)
		wire[10] ^= 0x01

		let connection = await connection(incoming: wire + bytes(Vectors.serverStream))

		await assertThrows(.integrityCheckFailed(sequenceNumber: 0)) { _ = try await connection.readUInt8() }
		await assertThrows(.failed) { _ = try await connection.readUInt8() }
	}

	func testABadRecordAlsoStopsWrites() async throws {
		var wire = bytes(Vectors.serverStream)
		wire[10] ^= 0x01

		let connection = await connection(incoming: wire)

		await assertThrows(.integrityCheckFailed(sequenceNumber: 0)) { _ = try await connection.readUInt8() }
		await assertThrows(.failed) { try await connection.write(data: Data(bytes(Vectors.clientMessage1))) }
		XCTAssertEqual(connection.base.written.count, 0)
	}

	func testAFailedBaseWriteIsFinal() async throws {
		let connection = await connection(MemoryConnection(incoming: bytes(Vectors.serverStream), failsFirstWrite: true))

		do {
			try await connection.write(data: Data([1]))
			XCTFail("no error")
		} catch {
			XCTAssertNil(encryptionError(error), "\(error)")
		}

		await assertThrows(.failed) { try await connection.write(data: Data([2])) }
		await assertThrows(.failed) { _ = try await connection.readUInt8() }
		XCTAssertEqual(connection.base.written.count, 0)
	}

	func testDecryptedBytesDoNotEscapeAfterAFailure() async throws {
		// Record 0 (12 bytes) is good, record 1 is damaged; a 13-byte read needs both.
		let all = records(bytes(Vectors.serverStream))
		var second = all[1]
		second[10] ^= 0x01

		let connection = await connection(incoming: all[0] + second)

		await assertThrows(.integrityCheckFailed(sequenceNumber: 1)) {
			_ = try await connection.read(minimumLength: 13, maximumLength: 13)
		}
		await assertThrows(.failed) { _ = try await connection.readUInt8() }
	}

	func testAnInvalidLengthStopsAllLaterReads() async throws {
		let connection = await connection(incoming: [0x00, 0x11] + [UInt8](repeating: 0, count: 64))

		await assertThrows(.invalidRecordLength(length: 17)) { _ = try await connection.readUInt8() }
		await assertThrows(.failed) { _ = try await connection.readUInt8() }
		// The record's bytes were not read.
		XCTAssertEqual(connection.base.remaining, 64)
	}

	func testAConnectionEndingInsideARecordStopsAllLaterReads() async throws {
		let connection = await connection(incoming: Array(bytes(Vectors.serverStream).prefix(30)))

		do {
			_ = try await connection.readUInt8()
			XCTFail("no error")
		} catch {
			XCTAssertNil(encryptionError(error), "\(error)")
		}

		await assertThrows(.failed) { _ = try await connection.readUInt8() }
	}

	func testConcurrentWritesReachTheWireInSequence() async throws {
		let connection = await connection(MemoryConnection(yieldsBeforeWriting: true))

		// Messages of different sizes, each starting with its number.
		let messages: [[UInt8]] = (0..<300).map { index in
			[UInt8(index >> 8), UInt8(truncatingIfNeeded: index)] + [UInt8](repeating: UInt8(truncatingIfNeeded: index), count: index % 40)
		}

		try await withThrowingTaskGroup(of: Void.self) { group in
			for message in messages {
				group.addTask { try await connection.write(data: Data(message)) }
			}

			try await group.waitForAll()
		}

		// Every record opens in wire order, and each one is a whole message.
		let opener = opener(.preferred)
		var received = [[UInt8]]()

		for record in records(connection.base.written) {
			received.append(try opener.open(Array(record.dropFirst(2))))
		}

		XCTAssertEqual(received.count, messages.count)
		XCTAssertEqual(Set(received.map(hex)), Set(messages.map(hex)))
	}

	/// The first base write fails while many writers wait at the gate: none of them sends
	/// anything.
	func testABaseWriteFailureStopsTheQueuedWriters() async throws {
		for _ in 0..<50 {
			let base = MemoryConnection(yieldsBeforeWriting: true, failsFirstWrite: true)
			let connection = await connection(base)

			let errors: [EncryptionError?] = await withTaskGroup(of: EncryptionError?.self) { group in
				for index in 0..<64 {
					group.addTask {
						do {
							try await connection.write(data: Data([UInt8(index)]))
							XCTFail("write \(index) succeeded")

							return nil
						} catch {
							// nil: the base connection's own error.
							return encryptionError(error)
						}
					}
				}

				var errors = [EncryptionError?]()

				for await error in group {
					errors.append(error)
				}

				return errors
			}

			XCTAssertEqual(errors.filter { $0 == nil }.count, 1)
			XCTAssertEqual(errors.filter { $0 == .failed }.count, 63)
			XCTAssertEqual(base.written.count, 0)
		}
	}

	/// Many writers race a read that hits a damaged record. Every write either sends one whole
	/// record, in sequence, or fails as `.failed`; after the read has failed, nothing more goes
	/// out.
	func testAReadFailureRacingWritersLeavesOnlyWholeRecords() async throws {
		for _ in 0..<50 {
			var wire = bytes(Vectors.serverStream)
			wire[10] ^= 0x01

			let base = MemoryConnection(incoming: wire, chunk: 1, yieldsBeforeWriting: true)
			let connection = await connection(base)

			let sent: Int = await withTaskGroup(of: Int.self) { group in
				for index in 0..<64 {
					group.addTask {
						do {
							try await connection.write(data: Data([UInt8(index), 1, 2, 3]))

							return 1
						} catch {
							XCTAssertEqual(encryptionError(error), .failed, "\(error)")

							return 0
						}
					}
				}

				group.addTask {
					do {
						_ = try await connection.readUInt8()
						XCTFail("the read succeeded")
					} catch { }

					return 0
				}

				var sent = 0

				for await count in group {
					sent += count
				}

				return sent
			}

			let written = base.written
			let opener = opener(.preferred)

			XCTAssertEqual(records(written).count, sent)

			for record in records(written) {
				XCTAssertEqual(Array(try opener.open(Array(record.dropFirst(2))).dropFirst()), [1, 2, 3])
			}

			await assertThrows(.failed) { try await connection.write(data: Data([9])) }
			XCTAssertEqual(base.written.count, written.count)
		}
	}
}

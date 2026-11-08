import Foundation
import XCTest
@testable import RoyalVNCKit

// Shared by the record layer tests: the oracle's vectors and keys, helpers, and an in-memory
// connection.

typealias Vectors = AppleRecordLayerVectors
typealias EncryptionError = VNCError.AppleSessionEncryptionError

func bytes(_ hex: String) -> [UInt8] {
	var result = [UInt8]()
	var index = hex.startIndex

	while index < hex.endIndex {
		let next = hex.index(index, offsetBy: 2)
		result.append(UInt8(hex[index..<next], radix: 16)!)
		index = next
	}

	return result
}

func hex(_ bytes: [UInt8]) -> String {
	let digits = Array("0123456789abcdef")

	return String(bytes.flatMap { [digits[Int($0 >> 4)], digits[Int($0 & 0x0f)]] })
}

let backends = AppleRecordCrypto.Backend.allCases.filter(\.isAvailable)

let keys = AppleRecordLayer.Keys(key: bytes(Vectors.key), iv: bytes(Vectors.iv))

func sealer(_ backend: AppleRecordCrypto.Backend, firstSequenceNumber: UInt32 = 0) -> AppleRecordLayer.Sealer {
	.init(direction: .init(keys: keys, firstSequenceNumber: firstSequenceNumber, backend: backend))
}

func opener(_ backend: AppleRecordCrypto.Backend, firstSequenceNumber: UInt32 = 0) -> AppleRecordLayer.Opener {
	.init(direction: .init(keys: keys, firstSequenceNumber: firstSequenceNumber, backend: backend))
}

/// The record layer error in `error`, if it is one.
func encryptionError(_ error: Error) -> EncryptionError? {
	guard case VNCError.protocol(.appleSessionEncryption(let underlying)) = error else { return nil }

	return underlying
}

func assertThrows(_ expected: EncryptionError,
						  file: StaticString = #filePath,
						  line: UInt = #line,
						  _ body: () throws -> Void) {
	do {
		try body()
		XCTFail("no error, expected \(expected)", file: file, line: line)
	} catch {
		XCTAssertEqual(encryptionError(error), expected, "\(error)", file: file, line: line)
	}
}

func assertThrows(_ expected: EncryptionError,
						  file: StaticString = #filePath,
						  line: UInt = #line,
						  _ body: () async throws -> Void) async {
	do {
		try await body()
		XCTFail("no error, expected \(expected)", file: file, line: line)
	} catch {
		XCTAssertEqual(encryptionError(error), expected, "\(error)", file: file, line: line)
	}
}

/// The records of a wire stream, each with its length.
func records(_ wire: [UInt8]) -> [[UInt8]] {
	var result = [[UInt8]]()
	var index = 0

	while index < wire.count {
		let length = Int(wire[index]) << 8 | Int(wire[index + 1])
		result.append(Array(wire[index..<(index + 2 + length)]))
		index += 2 + length
	}

	return result
}

/// An in-memory connection: reads hand out `incoming` at most `chunk` bytes at a time. At its
/// end they fail as closed, or, with `waitsAtEnd`, wait until `cancel()`. Writes collect in
/// `written`, optionally after yielding; `failsFirstWrite` fails the first one.
final class MemoryConnection: NetworkConnection {
	private let incoming: [UInt8]
	private let chunk: Int
	private let yieldsBeforeWriting: Bool
	private let waitsAtEnd: Bool
	private let failsFirstWrite: Bool

	private let lock = NSLock()
	private var offset = 0
	private var writtenBytes = [UInt8]()
	private var writeAttempts = 0
	private var isCancelled = false
	private var waiter: CheckedContinuation<Void, Never>?

	init(incoming: [UInt8] = [],
		 chunk: Int = .max,
		 yieldsBeforeWriting: Bool = false,
		 waitsAtEnd: Bool = false,
		 failsFirstWrite: Bool = false) {
		self.incoming = incoming
		self.chunk = chunk
		self.yieldsBeforeWriting = yieldsBeforeWriting
		self.waitsAtEnd = waitsAtEnd
		self.failsFirstWrite = failsFirstWrite
	}

	convenience init(settings: NetworkConnectionSettings) {
		self.init()
	}

	var remaining: Int {
		locked { incoming.count - offset }
	}

	var written: [UInt8] {
		locked { writtenBytes }
	}

	var status: NetworkConnectionStatus { .ready }
	var isReady: Bool { true }

	func setStatusUpdateHandler(_ statusUpdateHandler: NetworkConnectionStatusUpdateHandler?) { }
	func start(queue: DispatchQueue) { }

	func cancel() {
		let waiter: CheckedContinuation<Void, Never>? = locked {
			isCancelled = true
			defer { self.waiter = nil }

			return self.waiter
		}

		waiter?.resume()
	}

	func read(minimumLength: Int, maximumLength: Int) async throws -> Data {
		if waitsAtEnd, remaining < max(minimumLength, 1) {
			await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
				let resumeNow: Bool = locked {
					guard !isCancelled else { return true }

					waiter = continuation

					return false
				}

				if resumeNow { continuation.resume() }
			}

			throw VNCError.connection(.cancelled)
		}

		return try locked {
			let available = incoming.count - offset
			let count = min(maximumLength, max(minimumLength, min(chunk, available)))

			guard count > 0, count <= available else {
				throw VNCError.connection(.closed)
			}

			defer { offset += count }

			return Data(incoming[offset..<(offset + count)])
		}
	}

	func write(data: Data) async throws {
		if yieldsBeforeWriting {
			for _ in 0..<Int.random(in: 0...3) {
				await Task.yield()
			}
		}

		try locked {
			writeAttempts += 1

			if failsFirstWrite, writeAttempts == 1 {
				throw VNCError.connection(.closed)
			}

			writtenBytes += data
		}
	}

	private func locked<T>(_ body: () throws -> T) rethrows -> T {
		lock.lock()
		defer { lock.unlock() }

		return try body()
	}
}

func readAll(_ connection: AppleRecordLayerNetworkConnection<MemoryConnection>, count: Int) async throws -> [UInt8] {
	Array(try await connection.readBuffered(length: count))
}

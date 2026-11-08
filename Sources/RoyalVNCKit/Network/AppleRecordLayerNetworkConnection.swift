#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Dispatch

/// Forwards to another connection, in the clear until `startRecordLayer(keys:)`, then through
/// Apple's record layer (`AppleRecordLayer`) in both directions.
///
/// Reads come from one task at a time. Writes may come from several: each one is a whole
/// message, sealed and handed to the base connection in one order, so the records reach the
/// wire in the order of their sequence numbers. Once a record fails, every later read and
/// write throws.
final class AppleRecordLayerNetworkConnection<Base: NetworkConnection>: NetworkConnection {
	let base: Base

#if canImport(Glibc) || canImport(Android) || canImport(WinSDK)
	private let lock = Spinlock()
#else
	private let lock = NSLock()
#endif

	private var sealer: AppleRecordLayer.Sealer?
	private var opener: AppleRecordLayer.Opener?

	/// Writes in order, one at a time.
	private let writeGate = AsyncSerialGate()

	/// Verified plaintext not handed out yet. Reader only.
	private var pending = [UInt8]()
	private var pendingStart = 0

	init(base: Base) {
		self.base = base
	}

	convenience init(settings: NetworkConnectionSettings) {
		self.init(base: Base(settings: settings))
	}

	/// Whether the record layer carries the connection. Any thread.
	var isRecordLayerActive: Bool {
		lock.lock()
		defer { lock.unlock() }

		return opener != nil
	}

	/// Everything read and written from now on goes through the record layer. Call it after
	/// reading the rekey, before writing anything else; only once.
	func startRecordLayer(keys: AppleRecordLayer.Keys) {
		startRecordLayer(sealer: .init(keys: keys),
						 opener: .init(keys: keys))
	}

	func startRecordLayer(sealer: AppleRecordLayer.Sealer,
						  opener: AppleRecordLayer.Opener) {
		lock.lock()
		defer { lock.unlock() }

		precondition(self.opener == nil, "The record layer was started twice")

		self.sealer = sealer
		self.opener = opener
	}

	var status: NetworkConnectionStatus { base.status }
	var isReady: Bool { base.isReady }

	func setStatusUpdateHandler(_ statusUpdateHandler: NetworkConnectionStatusUpdateHandler?) {
		base.setStatusUpdateHandler(statusUpdateHandler)
	}

	func cancel() {
		base.cancel()
	}

	func start(queue: DispatchQueue) {
		base.start(queue: queue)
	}

	func read(minimumLength: Int,
			  maximumLength: Int) async throws -> Data {
		guard let opener = currentOpener() else {
			return try await base.read(minimumLength: minimumLength,
									   maximumLength: maximumLength)
		}

		guard maximumLength >= minimumLength,
			  maximumLength > 0 else {
			throw VNCError.protocol(.invalidData)
		}

		while pending.count - pendingStart < max(minimumLength, 1) {
			try await readRecord(opener: opener)
		}

		let count = min(maximumLength, pending.count - pendingStart)
		let data = Data(pending[pendingStart..<(pendingStart + count)])

		pendingStart += count

		if pendingStart == pending.count {
			pending.removeAll(keepingCapacity: true)
			pendingStart = 0
		}

		return data
	}

	func write(data: Data) async throws {
		await writeGate.enter()
		defer { writeGate.leave() }

		guard let sealer = currentSealer() else {
			try await base.write(data: data)

			return
		}

		// Records carry messages; there is no empty message to send.
		guard !data.isEmpty else { return }

		let records = try sealer.seal(Array(data))

		try await base.write(data: Data(records))
	}
}

private extension AppleRecordLayerNetworkConnection {
	func currentOpener() -> AppleRecordLayer.Opener? {
		lock.lock()
		defer { lock.unlock() }

		return opener
	}

	func currentSealer() -> AppleRecordLayer.Sealer? {
		lock.lock()
		defer { lock.unlock() }

		return sealer
	}

	/// Reads, checks and appends one record's body. Any failure, the connection's included,
	/// ends the record layer: the stream can't be picked up mid-record.
	func readRecord(opener: AppleRecordLayer.Opener) async throws {
		guard !opener.hasFailed else {
			throw VNCError.protocol(.appleSessionEncryption(.failed))
		}

		let body: [UInt8]

		do {
			let length = Int(try await base.readUInt16())

			guard AppleRecordLayer.isValidRecordLength(length) else {
				throw VNCError.protocol(.appleSessionEncryption(.invalidRecordLength(length: length)))
			}

			let ciphertext = try await base.readBuffered(length: length,
														 minimumChunkSize: 1,
														 maximumChunkSize: length)

			body = try opener.open(Array(ciphertext))
		} catch {
			opener.fail()

			throw error
		}

		if pendingStart > 0 {
			pending.removeFirst(pendingStart)
			pendingStart = 0
		}

		pending += body
	}
}

/// An async lock that lets one task in at a time, in the order they arrived.
final class AsyncSerialGate {
#if canImport(Glibc) || canImport(Android) || canImport(WinSDK)
	private let lock = Spinlock()
#else
	private let lock = NSLock()
#endif

	private var isBusy = false
	private var waiters = [CheckedContinuation<Void, Never>]()

	func enter() async {
		await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
			lock.lock()

			if isBusy {
				waiters.append(continuation)
				lock.unlock()
			} else {
				isBusy = true
				lock.unlock()

				continuation.resume()
			}
		}
	}

	func leave() {
		lock.lock()

		guard !waiters.isEmpty else {
			isBusy = false
			lock.unlock()

			return
		}

		let next = waiters.removeFirst()
		lock.unlock()

		next.resume()
	}
}

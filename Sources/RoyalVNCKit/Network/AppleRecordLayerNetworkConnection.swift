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
/// wire in the order of their sequence numbers. An empty write sends nothing.
///
/// Once the record layer is on, any failure (a bad record, sealing, or the base connection
/// failing a read or a write) is final for both directions: every later read and write throws,
/// bytes already decrypted included. The record layer stays installed, so nothing can go out
/// in the clear afterwards. Closing the connection is up to the owner (`VNCConnection` does on
/// any error).
final class AppleRecordLayerNetworkConnection<Base: NetworkConnection>: NetworkConnection {
	let base: Base

#if canImport(Glibc) || canImport(Android) || canImport(WinSDK)
	private let lock = Spinlock()
#else
	private let lock = NSLock()
#endif

	private var sealer: AppleRecordLayer.Sealer?
	private var opener: AppleRecordLayer.Opener?
	private var hasFailed = false

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

	/// Whether the record layer carries the connection; still true after it failed. Any thread.
	var isRecordLayerActive: Bool {
		lock.lock()
		defer { lock.unlock() }

		return opener != nil
	}

	/// Everything read and written from now on goes through the record layer. Waits for writes
	/// under way. Call it after reading the rekey, before reading anything else; only once.
	func startRecordLayer(keys: AppleRecordLayer.Keys,
						  backend: AppleRecordCrypto.Backend = .preferred) async {
		await writeGate.enter()
		defer { writeGate.leave() }

		install(sealer: .init(direction: .init(keys: keys, backend: backend)),
				opener: .init(direction: .init(keys: keys, backend: backend)))
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
		guard let opener = try currentOpener() else {
			return try await base.read(minimumLength: minimumLength,
									   maximumLength: maximumLength)
		}

		guard maximumLength >= minimumLength,
			  maximumLength > 0 else {
			throw VNCError.protocol(.invalidData)
		}

		do {
			while pending.count - pendingStart < max(minimumLength, 1) {
				try await readRecord(opener: opener)
			}
		} catch {
			markFailed()

			throw error
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

		guard let sealer = try currentSealer() else {
			try await base.write(data: data)

			return
		}

		guard !data.isEmpty else { return }

		do {
			let records = try sealer.seal(Array(data))

			try await base.write(data: Data(records))
		} catch {
			markFailed()

			throw error
		}
	}
}

private extension AppleRecordLayerNetworkConnection {
	/// The opener, nil before the record layer starts. Throws once it has failed.
	func currentOpener() throws -> AppleRecordLayer.Opener? {
		lock.lock()
		defer { lock.unlock() }

		guard !hasFailed else {
			throw VNCError.protocol(.appleSessionEncryption(.failed))
		}

		return opener
	}

	/// The sealer, nil before the record layer starts. Throws once it has failed.
	func currentSealer() throws -> AppleRecordLayer.Sealer? {
		lock.lock()
		defer { lock.unlock() }

		guard !hasFailed else {
			throw VNCError.protocol(.appleSessionEncryption(.failed))
		}

		return sealer
	}

	func install(sealer: AppleRecordLayer.Sealer,
				 opener: AppleRecordLayer.Opener) {
		lock.lock()
		defer { lock.unlock() }

		precondition(self.opener == nil, "The record layer was started twice")

		self.sealer = sealer
		self.opener = opener
	}

	func markFailed() {
		lock.lock()
		hasFailed = true
		lock.unlock()
	}

	/// Reads, checks and appends one record's body.
	func readRecord(opener: AppleRecordLayer.Opener) async throws {
		let length = Int(try await base.readUInt16())

		guard AppleRecordLayer.isValidRecordLength(length) else {
			throw VNCError.protocol(.appleSessionEncryption(.invalidRecordLength(length: length)))
		}

		let ciphertext = try await base.readBuffered(length: length,
													 minimumChunkSize: 1,
													 maximumChunkSize: length)

		let body = try opener.open(Array(ciphertext))

		if pendingStart > 0 {
			pending.removeFirst(pendingStart)
			pendingStart = 0
		}

		pending += body
	}
}

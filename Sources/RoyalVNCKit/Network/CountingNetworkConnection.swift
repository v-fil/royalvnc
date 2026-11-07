#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Dispatch

/// Forwards to another connection and counts the bytes read from it.
final class CountingNetworkConnection<Base: NetworkConnection>: NetworkConnection {
	let base: Base

#if canImport(Glibc) || canImport(Android) || canImport(WinSDK)
	private let lock = Spinlock()
#else
	private let lock = NSLock()
#endif

	private var received: UInt64 = 0

	init(settings: NetworkConnectionSettings) {
		self.base = Base(settings: settings)
	}

	/// Bytes read so far. Any thread.
	var bytesReceived: UInt64 {
		lock.lock()
		defer { lock.unlock() }

		return received
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
		let data = try await base.read(minimumLength: minimumLength,
									   maximumLength: maximumLength)

		count(data.count)

		return data
	}

	private func count(_ length: Int) {
		lock.lock()
		received &+= UInt64(length)
		lock.unlock()
	}

	func write(data: Data) async throws {
		try await base.write(data: data)
	}
}

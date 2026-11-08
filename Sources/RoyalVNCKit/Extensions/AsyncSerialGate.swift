#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// An async lock that lets one task in at a time, in the order they arrived. Every `enter()`
/// is paired with one `leave()`.
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

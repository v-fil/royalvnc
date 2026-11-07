#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// First in, first out; any thread. `next()` waits for an element.
final class Queue<T> {
#if canImport(Glibc) || canImport(Android) || canImport(WinSDK)
	private let lock = Spinlock()
#else
	private let lock = NSLock()
#endif

	private var list = [T]()
	private var waiter: CheckedContinuation<T?, Never>?
	private var isClosed = false

	func enqueue(_ element: T) {
		lock.lock()

		guard !isClosed else {
			lock.unlock()

			return
		}

		if let waiter {
			self.waiter = nil
			lock.unlock()

			waiter.resume(returning: element)

			return
		}

		list.append(element)
		lock.unlock()
	}

	func dequeue() -> T? {
		lock.lock()
		defer { lock.unlock() }

		guard !list.isEmpty else { return nil }

		return list.removeFirst()
	}

	/// The next element, waiting for one if the queue is empty. Nil once closed.
	func next() async -> T? {
		await withCheckedContinuation { continuation in
			take(continuation)
		}
	}

	func clear() {
		lock.lock()
		list.removeAll()
		lock.unlock()
	}

	/// Drops the elements and ends a waiting `next()`. Later elements are ignored.
	func close() {
		lock.lock()
		isClosed = true
		list.removeAll()

		let waiter = self.waiter
		self.waiter = nil
		lock.unlock()

		waiter?.resume(returning: nil)
	}

	var isEmpty: Bool {
		lock.lock()
		defer { lock.unlock() }

		return list.isEmpty
	}

	private func take(_ continuation: CheckedContinuation<T?, Never>) {
		lock.lock()

		if !list.isEmpty {
			let element = list.removeFirst()
			lock.unlock()

			continuation.resume(returning: element)
		} else if isClosed {
			lock.unlock()

			continuation.resume(returning: nil)
		} else {
			waiter = continuation
			lock.unlock()
		}
	}
}

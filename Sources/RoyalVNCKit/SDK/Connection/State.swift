#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif


extension VNCConnection {
    final class State {
		var disconnectRequested = false

		var serverProtocolVersion: VNCProtocol.ProtocolVersion?
		var agreedProtocolVersion: VNCProtocol.ProtocolVersion?

		var isTightSecurityEnabled = false

		var framebufferWidth: UInt16 = 0
		var framebufferHeight: UInt16 = 0

		var serverPixelFormat: VNCProtocol.PixelFormat?
		var pixelFormat: VNCProtocol.PixelFormat?

		var desktopName: String?

		var incrementalUpdatesEnabled = false

		var areContinuousUpdatesSupported = false
		var areContinuousUpdatesEnabled = false

		/// An Apple pasteboard fetch is outstanding: only its answer is taken.
		var isApplePasteboardFetchPending = false

		/// Replaces the settings' frame encodings once set. Under the scaling lock.
		var frameEncodings: [VNCFrameEncodingType]?

		struct Scaling {
			struct Pending {
				let factor: Double
				let size: VNCSize
				let deadline: UInt64
			}

			var scale = 1.0
			var pending: Pending?
			/// The new size applies; waiting for its first full frame.
			var awaitingFullFrame = false
		}

		private var scaling = Scaling()

#if canImport(Glibc) || canImport(Android) || canImport(WinSDK)
		private let statisticsLock = Spinlock()
#else
		private let statisticsLock = NSLock()
#endif

		private var handlingSeconds = 0.0

		/// Any thread.
		func withScaling<Result>(_ body: (inout Scaling) -> Result) -> Result {
			statisticsLock.lock()
			defer { statisticsLock.unlock() }

			return body(&scaling)
		}

		/// Any thread.
		var secondsHandlingMessages: Double {
			statisticsLock.lock()
			defer { statisticsLock.unlock() }

			return handlingSeconds
		}

		func addSecondsHandlingMessages(_ seconds: Double) {
			statisticsLock.lock()
			handlingSeconds += seconds
			statisticsLock.unlock()
		}
	}
}

extension VNCConnection.State {
	var isAppleRemoteDesktop: Bool {
		return serverProtocolVersion?.isAppleRemoteDesktop ?? false
	}
}

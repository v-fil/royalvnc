#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Dispatch

// MARK: - Raw Input
public extension VNCConnection {
	/// Sends a pointer event with this button mask (bit 0 left, 1 middle, 2 right, 3 and 4
	/// wheel up and down), in the server's native pixels even while its screen is scaled.
	/// Leaves the button state of the other mouse APIs alone. Any thread.
	func sendPointerEvent(x: UInt16, y: UInt16, buttonMask: UInt8) {
		enqueueMouseEvent(buttons: .init(rawValue: buttonMask),
						  nonNormalizedX: x,
						  nonNormalizedY: y)
	}

	/// Sends an X11 keysym as it is, without the modifier remapping of `keyDown(_:)`. Any thread.
	func sendKeyEvent(keysym: UInt32, isDown: Bool) {
		guard settings.inputMode != .none else { return }

		enqueueClientToServerMessage(VNCProtocol.KeyEvent(isDown: isDown, key: keysym))
	}
}

// MARK: - Encodings
public extension VNCConnection {
	/// Replaces the frame encodings of `settings` on the live connection and asks for a full
	/// frame, which arrives in the new encoding. Any thread.
	func updateFrameEncodings(_ frameEncodings: [VNCFrameEncodingType]) {
		state.withScaling { _ in state.frameEncodings = frameEncodings }

		guard let encodings = try? orderedEncodingTypes() else { return }

		enqueueClientToServerMessage(VNCProtocol.SetEncodings(encodingTypes: encodings))
		enqueueFullFramebufferUpdateRequest()
	}
}

// MARK: - Apple Server Scaling
public extension VNCConnection {
	/// The scale of the server's screen in effect, relative to its native size (Apple only).
	var serverScale: Double {
		state.withScaling { $0.scale }
	}

	/// Whether a server scale change is under way: from the request until the first full
	/// frame at the new size. Once the new size applies, the framebuffer holds the old
	/// picture's top-left part until that frame arrives, so `didFinishFramebufferUpdate` is
	/// not called meanwhile.
	var isRescaling: Bool {
		state.withScaling { $0.pending != nil }
	}

	/// Asks Apple Screen Sharing to scale its screen to `factor` (0, 1] of the native size
	/// (SetServerScaling). Ignored on other servers and while a change is under way. Any thread.
	///
	/// When the scale applies, the server sends DesktopSize in its update stream: updates
	/// before it are of the old size, after it of the new one. The framebuffer is resized
	/// there (`didResizeFramebuffer`, keeping the picture's top-left part), and a full frame
	/// asked for.
	func setServerScale(_ factor: Double) {
		guard state.isAppleRemoteDesktop,
			  factor > 0, factor <= 1 else { return }

		let native = serverInitSize

		guard native.width > 0, native.height > 0 else { return }

		// Rounded up, like the server (2234 at 1/4 gives 559 rows).
		let newSize = VNCSize(width: UInt16((Double(native.width) * factor).rounded(.up)),
							  height: UInt16((Double(native.height) * factor).rounded(.up)))

		let deadline = DispatchTime.now().uptimeNanoseconds + Self.rescaleTimeout

		let started: Bool = state.withScaling { scaling in
			guard scaling.pending == nil, factor != scaling.scale else { return false }

			scaling.pending = .init(factor: factor, size: newSize, deadline: deadline)

			return true
		}

		guard started else { return }

		logger.logInfo("Server scale \(serverScale) -> \(factor) (\(newSize.width)x\(newSize.height))")

		enqueueClientToServerMessage(AppleClientMessage.setServerScaling(factor))

		// A server that never answers (or answers with an unexpected size) must not block
		// later changes.
		Task(priority: taskPriority) { [weak self] in
			try? await Task.sleep(seconds: Double(Self.rescaleTimeout) / 1e9 + 0.1)

			guard let self else { return }

			let expired: Bool = state.withScaling { scaling in
				guard let pending = scaling.pending, pending.deadline == deadline else { return false }

				scaling.pending = nil
				scaling.awaitingFullFrame = false

				return true
			}

			if expired {
				logger.logError("Server scale \(factor): no new size and full frame within the time limit")
			}
		}
	}
}

// MARK: - Internal
extension VNCConnection {
	/// Nanoseconds a scale change may take until its full frame has arrived.
	static let rescaleTimeout: UInt64 = 20_000_000_000

	func enqueueFullFramebufferUpdateRequest() {
		guard let framebuffer else { return }

		enqueueClientToServerMessage(VNCProtocol.FramebufferUpdateRequest(incremental: false,
																		  xPosition: 0,
																		  yPosition: 0,
																		  width: framebuffer.size.width,
																		  height: framebuffer.size.height))
	}

	/// The server's screen changed size (DesktopSize), in the update stream. Receive task.
	func serverScreenSizeDidChange(_ newSize: VNCSize) {
		// The server starts its 1011 tile state over at the new size.
		appleMVSEncoding.reset()

		state.withScaling { scaling in
			guard let pending = scaling.pending, pending.size == newSize else { return }

			scaling.scale = pending.factor
			scaling.awaitingFullFrame = true
		}
	}

	/// Notes a finished framebuffer update for a scale change waiting for its full frame.
	/// Returns whether the update may be shown.
	func noteFinishedUpdateForRescale(_ rectangles: [VNCProtocol.Rectangle],
									  framebufferSize: VNCSize) -> Bool {
		state.withScaling { scaling in
			guard scaling.pending != nil else { return true }

			guard scaling.awaitingFullFrame, !rectangles.isEmpty else { return false }

			let minX = rectangles.map({ Int($0.xPosition) }).min() ?? 0
			let minY = rectangles.map({ Int($0.yPosition) }).min() ?? 0
			let maxX = rectangles.map({ Int($0.xPosition) + Int($0.width) }).max() ?? 0
			let maxY = rectangles.map({ Int($0.yPosition) + Int($0.height) }).max() ?? 0

			guard minX == 0, minY == 0,
				  maxX == Int(framebufferSize.width), maxY == Int(framebufferSize.height) else { return false }

			scaling.pending = nil
			scaling.awaitingFullFrame = false

			return true
		}
	}
}

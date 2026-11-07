#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(CoreGraphics)
import CoreGraphics
#endif

// MARK: - Queue Management
extension VNCConnection {
	func enqueueKeyEvent(key: VNCKeyCode,
						 isDown: Bool) {
		guard settings.inputMode != .none else { return }

		let isARD = state.isAppleRemoteDesktop
		let keyCode = key.rawValue(forAppleRemoteDesktop: isARD)

		let keyEvent = VNCProtocol.KeyEvent(isDown: isDown,
											key: keyCode)

		logger.logDebug("Enqueuing Key \(keyEvent.description)")

		enqueueClientToServerMessage(keyEvent)
	}

    func enqueueMouseEvent(nonNormalizedX: UInt16,
                           nonNormalizedY: UInt16) {
        guard settings.inputMode != .none else { return }

        let normalizedPosition = normalizedMousePosition(x: nonNormalizedX,
                                                         y: nonNormalizedY)

        enqueueMouseEvent(buttons: mouseButtonState,
                          position: normalizedPosition)
    }

    func enqueueMouseEvent(buttons: VNCProtocol.MousePointerButton,
                           nonNormalizedX: UInt16,
                           nonNormalizedY: UInt16) {
        guard settings.inputMode != .none else { return }

        let normalizedPosition = normalizedMousePosition(x: nonNormalizedX,
                                                         y: nonNormalizedY)

        enqueueMouseEvent(buttons: buttons,
                          position: normalizedPosition)
    }

	func enqueueMouseEvent(buttons: VNCProtocol.MousePointerButton,
						   position: VNCProtocol.MousePosition) {
		guard settings.inputMode != .none else { return }

		let pointerEvent = VNCProtocol.PointerEvent(buttons: buttons,
													position: position)

		enqueueClientToServerMessage(pointerEvent)
	}

	func enqueueClientCutTextMessage(_ text: String) {
		let clientCutTextMessage = VNCProtocol.ClientCutText(text: text)

		enqueueClientToServerMessage(clientCutTextMessage)
	}

	func enqueueClientToServerMessage(_ message: VNCSendableMessage) {
		clientToServerMessageQueue.enqueue(message)
	}

    func normalizedMousePosition(x: UInt16,
                                 y: UInt16) -> VNCProtocol.MousePosition {
        var normalizedX = x
        var normalizedY = y

        var framebufferWidth = framebuffer?.size.width ?? 0
        var framebufferHeight = framebuffer?.size.height ?? 0

        // Apple servers take native pixels even while their screen is scaled
        if state.isAppleRemoteDesktop {
            framebufferWidth = max(framebufferWidth, state.framebufferWidth)
            framebufferHeight = max(framebufferHeight, state.framebufferHeight)
        }

        if normalizedY > framebufferHeight {
            normalizedY = framebufferHeight
        }

        if normalizedX > framebufferWidth {
            normalizedX = framebufferWidth
        }

        let normalizedPosition = VNCProtocol.MousePosition(x: normalizedX,
                                                           y: normalizedY)

        return normalizedPosition
    }
}

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Dispatch

// MARK: - Server to Client Messages
extension VNCConnection {
	func startReceiveLoop() {
        logger.logDebug("Starting receive loop")

        receiveTask = Task(priority: taskPriority) {
			while !state.disconnectRequested,
                  connection.isReady {
				do {
					try await receive()
				} catch {
					handleBreakingError(error)
				}
			}
		}
	}
}

private extension VNCConnection {
	func receive() async throws {
		guard !state.disconnectRequested else {
			// Just ignore, since disconnect has already been requested
			return
		}

        guard connection.isReady else {
			throw VNCError.connection(.notReady)
		}

		let serverToClientMessage = try await VNCProtocol.ServerToClientMessage.receive(connection: connection)

		let start = DispatchTime.now().uptimeNanoseconds

		defer {
			let elapsed = DispatchTime.now().uptimeNanoseconds - start
			state.addSecondsHandlingMessages(Double(elapsed) / 1e9)
		}

		try await didReceive(messageType: serverToClientMessage.messageType)
	}

	func didReceive(messageType: UInt8) async throws {
		switch messageType {
			case VNCProtocol.FramebufferUpdate.messageType:
				try await handleFramebufferUpdateMessage()

			case VNCProtocol.SetColourMapEntries.messageType:
				try await handleSetColourMapEntriesMessage()

			case VNCProtocol.ServerCutText.messageType:
				try await handleServerCutTextMessage()

			case VNCProtocol.Bell.messageType:
				try await handleBellMessage()

			case VNCProtocol.EndOfContinuousUpdates.messageType:
				try await handleEndOfContinuousUpdatesMessage()

			case VNCProtocol.AppleMiscStatus.messageType where state.isAppleRemoteDesktop:
				try await handleAppleMiscStatusMessage()

			case VNCProtocol.ApplePasteboardContents.messageType where state.isAppleRemoteDesktop:
				try await handleApplePasteboardContentsMessage()

			default:
				throw VNCError.protocol(.unsupportedServerToClientMessage(messageType: messageType))
		}
	}

	func handleFramebufferUpdateMessage() async throws {
		guard let framebuffer = framebuffer else {
			throw VNCError.protocol(.framebufferUpdateReceivedWithoutFramebuffer)
		}

		logger.logDebug("Receiving Framebuffer Update")

		let framebufferUpdate = try await VNCProtocol.FramebufferUpdate.receive(connection: connection,
																				currentFramebuffer: { [weak self] in self?.framebuffer },
																				encodings: encodings,
																				logger: logger)

		logger.logDebug("Received Framebuffer Update: \(framebufferUpdate)")

		let currentFramebuffer = self.framebuffer ?? framebuffer

		if noteFinishedUpdateForRescale(framebufferUpdate.rectangles,
										framebufferSize: currentFramebuffer.size),
		   let sessionDelegate {
			let rectangles = framebufferUpdate.rectangles.map {
				VNCUpdatedRectangle(region: $0.region, encodingType: $0.encodingType)
			}

			sessionDelegate.connection(self,
									   didFinishFramebufferUpdate: currentFramebuffer,
									   rectangles: rectangles)
		}

		/*
		// Write out the framebuffer for testing purposes
		try framebuffer.writeSurface()
		*/

		try await sendFramebufferUpdateRequest()
	}

	func handleSetColourMapEntriesMessage() async throws {
		guard let framebuffer = framebuffer else {
			throw VNCError.protocol(.setColourMapEntriesReceivedWithoutFramebuffer)
		}

		logger.logDebug("Receiving Colour Map Entries")

		let colourMapEntries = try await VNCProtocol.SetColourMapEntries.receive(connection: connection,
																				 logger: logger)

		logger.logDebug("Received Colour Map Entries")

		framebuffer.updateColorMap(colourMapEntries)
	}

	func handleServerCutTextMessage() async throws {
		logger.logDebug("Receiving Clipboard Text from Server")

		let serverCutText = try await VNCProtocol.ServerCutText.receive(connection: connection,
																		logger: logger)

		let text = serverCutText.text

		logger.logDebug("Received Clipboard Text from Server")

		deliverServerClipboardText(text)
	}

	func deliverServerClipboardText(_ text: String) {
		if forwardsServerClipboard {
			sessionDelegate?.connection(self, didReceiveClipboardText: text)
		}

		guard settings.isClipboardRedirectionEnabled else { return }

		clipboard.text = text
	}

	func handleAppleMiscStatusMessage() async throws {
		let status = try await VNCProtocol.AppleMiscStatus.receive(connection: connection)

		guard status.isPasteboardChanged,
			  forwardsServerClipboard || settings.isClipboardRedirectionEnabled else { return }

		state.isApplePasteboardFetchPending = true

		enqueueClientToServerMessage(AppleClientMessage.pasteboardFetch)
	}

	func handleApplePasteboardContentsMessage() async throws {
		let contents = try await VNCProtocol.ApplePasteboardContents.receive(connection: connection)

		// The server can trigger a fetch at any time with a change notice; contents that
		// arrive without one are not taken.
		guard state.isApplePasteboardFetchPending else {
			logger.logDebug("Ignoring Apple pasteboard contents that were not asked for")

			return
		}

		state.isApplePasteboardFetchPending = false

		guard let text = contents.text else { return }

		deliverServerClipboardText(text)
	}

	func handleBellMessage() async throws {
		logger.logDebug("Receiving Bell Message from Server")

		_ = try await VNCProtocol.Bell.receive(connection: connection,
											   logger: logger)

		logger.logDebug("Received Bell Message from Server")

		systemSound.play()
	}

	func handleEndOfContinuousUpdatesMessage() async throws {
		let first = !state.areContinuousUpdatesSupported

		state.areContinuousUpdatesSupported = true
		state.areContinuousUpdatesEnabled = false

		if first {
			logger.logDebug("Continuous Updates supported (server sent EndOfContinuousUpdates)")
		} else {
			logger.logDebug("Disabling Continuous Updates")
		}

		try await sendFramebufferUpdateRequest()
	}
}

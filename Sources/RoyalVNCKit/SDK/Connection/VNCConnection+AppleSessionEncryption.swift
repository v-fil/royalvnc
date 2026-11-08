#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Apple Session Encryption
extension VNCConnection {
	/// Whether the client asks an Apple server for its pasteboard.
	var wantsApplePasteboard: Bool {
		forwardsServerClipboard || settings.isClipboardRedirectionEnabled
	}

	/// The wrap key to keep from an Apple Remote Desktop login: only when session encryption is
	/// on and the server is Apple's.
	static func appleRecordLayerWrapKey(_ wrapKey: [UInt8],
										isEnabled: Bool,
										isAppleServer: Bool) -> [UInt8]? {
		isEnabled && isAppleServer ? wrapKey : nil
	}

	/// After ServerInit, before any other client message: starts the record layer on
	/// `connection`. Any failure ends the session.
	func startAppleSessionEncryption(wrapKey: [UInt8]) async throws {
		logger.logDebug("Sending SetEncryption, then waiting for the session key")

		let arrival = try await Self.startAppleSessionEncryption(
			connection: connection,
			wrapKey: wrapKey,
			pasteboard: wantsApplePasteboard,
			timeout: appleRekeyTimeout,
			onTimeout: { [weak self] in
				self?.handleBreakingError(VNCError.protocol(.appleSessionEncryption(.rekeyTimedOut)))
			},
			isCancelled: { [weak self] in
				self?.state.disconnectRequested ?? true
			})

		state.isApplePasteboardChangedBeforeRekey = arrival.isPasteboardChanged

		logger.logInfo("Session encryption on (key generation \(arrival.rekey.generation))")
	}

	/// What came with the rekey.
	struct AppleRekeyArrival {
		let rekey: AppleRecordLayer.Rekey

		/// A MiscStatus before the rekey said the server's pasteboard changed.
		let isPasteboardChanged: Bool
	}

	/// Sends the prelude and SetEncryption in the clear, waits for the rekey and starts the
	/// record layer. `onTimeout` runs if the rekey has not come within `timeout` seconds (it
	/// should end the session, which ends the wait). If `isCancelled()` once the rekey is in,
	/// the record layer is not started and this throws.
	static func startAppleSessionEncryption<Base: NetworkConnection>(connection: AppleRecordLayerNetworkConnection<Base>,
																	 wrapKey: [UInt8],
																	 pasteboard: Bool,
																	 timeout: Double,
																	 onTimeout: @escaping () -> Void,
																	 isCancelled: () -> Bool,
																	 backend: AppleRecordCrypto.Backend = .preferred) async throws -> AppleRekeyArrival {
		for message in AppleClientMessage.prelude(pasteboard: pasteboard) + AppleClientMessage.setEncryption {
			try await message.send(connection: connection)
		}

		let watchdog = Task {
			try await Task.sleep(seconds: timeout)

			onTimeout()
		}

		defer { watchdog.cancel() }

		let arrival = try await receiveAppleRekey(connection: connection,
												  wrapKey: wrapKey,
												  backend: backend)

		// Timed out or disconnected meanwhile: the session has already ended.
		guard !isCancelled() else {
			throw VNCError.connection(.cancelled)
		}

		await connection.startRecordLayer(keys: arrival.rekey.keys, backend: backend)

		return arrival
	}

	/// Reads cleartext server messages up to the rekey and returns what it carries. Bells,
	/// MiscStatus and empty updates are stepped over; anything else fails. Nothing the client
	/// asked for can come first: no pixel format, encodings or update request has been sent.
	static func receiveAppleRekey(connection: NetworkConnectionReading,
								  wrapKey: [UInt8],
								  backend: AppleRecordCrypto.Backend = .preferred) async throws -> AppleRekeyArrival {
		var isPasteboardChanged = false

		while true {
			let messageType = try await connection.readUInt8()

			switch messageType {
				case VNCProtocol.FramebufferUpdate.messageType:
					try await connection.readPadding()

					let rectangleCount = try await connection.readUInt16()

					guard rectangleCount != 0 else { continue }

					// Everything after the rekey rectangle is in records.
					guard rectangleCount == 1 else {
						throw VNCError.protocol(.appleSessionEncryption(.invalidRekey))
					}

					let rectangle = try await VNCProtocol.Rectangle.receive(connection: connection)

					guard rectangle.encodingType == AppleRecordLayer.rekeyEncodingType else {
						throw VNCError.protocol(.appleSessionEncryption(.invalidRekey))
					}

					let body = try await connection.readBuffered(length: AppleRecordLayer.rekeyLength)

					let rekey = try AppleRecordLayer.unwrapRekey(Array(body),
																 wrapKey: wrapKey,
																 backend: backend)

					return .init(rekey: rekey, isPasteboardChanged: isPasteboardChanged)

				case VNCProtocol.Bell.messageType:
					continue

				case VNCProtocol.AppleMiscStatus.messageType:
					// Padding, a u16 length, that many bytes; the command is the u16 at
					// offset 2 of them, as AppleMiscStatus reads it.
					try await connection.readPadding()

					let length = Int(try await connection.readUInt16())

					guard length <= maximumMiscStatusLength else {
						throw VNCError.protocol(.appleSessionEncryption(.unexpectedMessageBeforeRekey(messageType: messageType)))
					}

					let body = Array(try await connection.readBuffered(length: length))

					if body.count >= 4,
					   UInt16(body[2]) << 8 | UInt16(body[3]) == VNCProtocol.AppleMiscStatus.pasteboardChangedCommand {
						isPasteboardChanged = true
					}

				default:
					throw VNCError.protocol(.appleSessionEncryption(.unexpectedMessageBeforeRekey(messageType: messageType)))
			}
		}
	}

	/// MiscStatus bodies are a few bytes.
	private static let maximumMiscStatusLength = 1024
}

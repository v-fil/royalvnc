#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Apple Session Encryption
extension VNCConnection {
	/// Seconds the server may take to send its key once asked.
	static let appleRekeyTimeout = 10.0

	/// After ServerInit, before any other client message: sends the cleartext prelude and
	/// SetEncryption, waits for the rekey and starts the record layer. Any failure ends the
	/// session.
	func startAppleSessionEncryption(wrapKey: [UInt8]) async throws {
		// Messages that must go out in the clear: the pasteboard notices are not turned on
		// by a request inside the record layer.
		var prelude = [AppleClientMessage.viewerInfo, AppleClientMessage.setModeControl]

		if forwardsServerClipboard || settings.isClipboardRedirectionEnabled {
			prelude.append(AppleClientMessage.autoPasteboardStart)
		}

		prelude.append(AppleClientMessage.setEncryptionRequestRekey)
		prelude.append(AppleClientMessage.setEncryptionDecryptReceived)

		for message in prelude {
			try await message.send(connection: connection)
		}

		logger.logDebug("Sent SetEncryption, waiting for the session key")

		let watchdog = Task(priority: taskPriority) { [weak self] in
			try await Task.sleep(seconds: Self.appleRekeyTimeout)

			self?.handleBreakingError(VNCError.protocol(.appleSessionEncryption(.rekeyTimedOut)))
		}

		defer { watchdog.cancel() }

		let rekey = try await Self.receiveAppleRekey(connection: connection,
													 wrapKey: wrapKey)

		// Timed out or disconnected meanwhile: the session has already ended.
		guard !state.disconnectRequested else {
			throw VNCError.connection(.cancelled)
		}

		connection.startRecordLayer(keys: rekey.keys)

		logger.logInfo("Session encryption on (key generation \(rekey.generation))")
	}

	/// Reads cleartext server messages up to the rekey and returns what it carries. Bells,
	/// MiscStatus and empty updates are stepped over; anything else fails. Nothing the client
	/// asked for can come first: no pixel format, encodings or update request has been sent.
	static func receiveAppleRekey(connection: NetworkConnectionReading,
								  wrapKey: [UInt8],
								  backend: AppleRecordCrypto.Backend = .preferred) async throws -> (generation: UInt32, keys: AppleRecordLayer.Keys) {
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

					return try AppleRecordLayer.unwrapRekey(Array(body),
															wrapKey: wrapKey,
															backend: backend)

				case VNCProtocol.Bell.messageType:
					continue

				case VNCProtocol.AppleMiscStatus.messageType:
					// Padding, a u16 length, that many bytes.
					try await connection.readPadding()

					let length = Int(try await connection.readUInt16())

					guard length <= maximumMiscStatusLength else {
						throw VNCError.protocol(.appleSessionEncryption(.unexpectedMessageBeforeRekey(messageType: messageType)))
					}

					try await connection.readPadding(length: length)

				default:
					throw VNCError.protocol(.appleSessionEncryption(.unexpectedMessageBeforeRekey(messageType: messageType)))
			}
		}
	}

	/// MiscStatus bodies are a few bytes.
	private static let maximumMiscStatusLength = 1024
}

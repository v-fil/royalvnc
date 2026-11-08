#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

public extension VNCError {
	/// A failure of Apple's session encryption (the record layer). Each one ends the session:
	/// once encryption was asked for, nothing more is sent or taken in the clear.
	enum AppleSessionEncryptionError: Error, Equatable, LocalizedError {
		/// The server did not send the key within the time limit after it was asked for.
		case rekeyTimedOut

		/// Before the key, the server sent a message other than a bell, a status message or
		/// the key itself.
		case unexpectedMessageBeforeRekey(messageType: UInt8)

		/// The update that should carry the key held another encoding or more than one
		/// rectangle.
		case invalidRekey

		/// The server sent a new key during the session. It is not followed.
		case unexpectedRekey

		/// A record's length is not a whole number of blocks of at least the smallest record.
		case invalidRecordLength(length: Int)

		/// A record failed its integrity check: damaged, replayed, reordered or out of step.
		case integrityCheckFailed(sequenceNumber: UInt32)

		/// A record's body and filler do not add up to its length.
		case invalidRecordBody(bodyLength: Int, recordLength: Int)

		/// The record counter of one direction would wrap around.
		case sequenceNumberExhausted

		/// Encryption or decryption itself failed.
		case cipherFailed

		/// An earlier record failed; the record layer takes nothing more.
		case failed

		// MARK: - LocalizedError
		public var errorDescription: String? {
			// TODO: Localize
			switch self {
				case .rekeyTimedOut:
					return "The server did not send its session key in time."
				case .unexpectedMessageBeforeRekey(let messageType):
					return "The server sent message \(messageType) before its session key."
				case .invalidRekey:
					return "The server's session key message was malformed."
				case .unexpectedRekey:
					return "The server changed the session key during the session."
				case .invalidRecordLength(let length):
					return "An encrypted record had an invalid length (\(length))."
				case .integrityCheckFailed(let sequenceNumber):
					return "Encrypted record \(sequenceNumber) failed its integrity check."
				case .invalidRecordBody(let bodyLength, let recordLength):
					return "An encrypted record of \(recordLength) bytes claimed a body of \(bodyLength) bytes."
				case .sequenceNumberExhausted:
					return "The session ran out of record numbers."
				case .cipherFailed:
					return "Encryption failed."
				case .failed:
					return "Session encryption failed earlier."
			}
		}
	}
}

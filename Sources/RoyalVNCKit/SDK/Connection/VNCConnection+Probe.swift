#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Dispatch

/// What a server offers before any login: its protocol version and security types.
public struct VNCServerProbe {
	/// The server's protocol version, e.g. "RFB 003.889" (Apple Screen Sharing).
	public let protocolVersion: String

	/// The security types in the server's order, as sent (including ones this library can't use).
	public let securityTypes: [UInt8]

	/// The offered types this library can log in with, in the server's order.
	public let authenticationTypes: [VNCAuthenticationType]

	/// Whether the server announced protocol version 3.889 (Apple Screen Sharing).
	public var isAppleServer: Bool { protocolVersion == "RFB 003.889" }
}

public extension VNCConnection {
	/// Connects, reads the server's protocol version and security types, and closes the
	/// connection without choosing a type, so no login is attempted. Useful to choose a login
	/// type before asking for credentials, or to pin the type a host offered.
	///
	/// Throws on connection errors, after `timeout` seconds, or when the server offers no
	/// security types (`VNCError.authentication(.serverOfferedNoAuthTypes(reason:))`).
	static func probeServer(hostname: String,
							port: UInt16,
							timeout: Double = 10) async throws -> VNCServerProbe {
		let connection = BaseNetworkConnection(settings: .init(connectionTimeout: max(1, Int(timeout.rounded(.up))),
															   host: hostname,
															   port: port))

		let queue = DispatchQueue(label: "com.royalapps.royalvnc.probe")
		let ready = ProbeReadiness()

		connection.setStatusUpdateHandler { status in
			switch status {
				case .ready:
					ready.finish(nil)
				case .waiting(let error), .failed(let error):
					ready.finish(VNCError.connection(.failed(error)))
				case .cancelled:
					ready.finish(VNCError.connection(.cancelled))
				default:
					break
			}
		}

		// Cancelling the connection fails a pending wait or read, so a silent server can't hang the probe.
		let timer = Task {
			try await Task.sleep(seconds: timeout)
			connection.cancel()
		}

		defer {
			timer.cancel()
			connection.setStatusUpdateHandler(nil)
			connection.cancel()
		}

		connection.start(queue: queue)

		try await ready.wait()

		let version = try await VNCProtocol.ProtocolVersion.receive(connection: connection)

		// Like the handshake: answer with the server's version, at most 3.8. Versions before 3.7
		// have the server choose the type, so there is no list to read.
		guard version.majorVersion == 3, version.minorVersion >= 7 else {
			throw VNCError.protocol(.invalidData)
		}

		try await VNCProtocol.ProtocolVersion.send(connection: connection,
												   protocolVersion: .init(majorVersion: 3,
																		  minorVersion: min(version.minorVersion, 8)))

		let number = try await VNCProtocol.NumberOfSecurityTypes.receive(connection: connection).number

		guard number > 0 else {
			let reason = try? await VNCProtocol.NumberOfSecurityTypes.receiveFailureReason(connection: connection)

			throw VNCError.authentication(.serverOfferedNoAuthTypes(reason: reason))
		}

		let types = try await VNCProtocol.SecurityTypes.receive(connection: connection, number: number)

		let usable: [VNCAuthenticationType] = types.securityTypes.compactMap {
			switch $0 {
				case .vnc: .vnc
				case .diffieHellman: .appleRemoteDesktop
				case .ultraVNCMSLogonII: .ultraVNCMSLogonII
				default: nil
			}
		}

		return .init(protocolVersion: version.protocolVersion,
					 securityTypes: types.authTypes,
					 authenticationTypes: usable)
	}
}

/// One-shot wait for the connection to become ready or fail, whichever comes first.
private final class ProbeReadiness: @unchecked Sendable {
	private let lock = NSLock()
	private var result: Result<Void, Error>?
	private var continuation: CheckedContinuation<Void, Error>?

	func finish(_ error: Error?) {
		lock.lock()

		guard result == nil else {
			lock.unlock()

			return
		}

		let result: Result<Void, Error> = error.map { .failure($0) } ?? .success(())
		self.result = result
		let continuation = self.continuation
		self.continuation = nil

		lock.unlock()

		continuation?.resume(with: result)
	}

	func wait() async throws {
		try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
			lock.lock()

			if let result {
				lock.unlock()
				continuation.resume(with: result)
			} else {
				self.continuation = continuation
				lock.unlock()
			}
		}
	}
}

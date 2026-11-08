#if canImport(Network)
import Foundation
import Network
import XCTest
@testable import RoyalVNCKit

// The whole client handshake against a scripted Apple server in this process, on 127.0.0.1:
// the type-30 login, the cleartext prelude, the rekey and the records after it, and the
// sessions that must stay in the clear.

private typealias Vectors = AppleRecordLayerVectors

private func bytes(_ hex: String) -> [UInt8] {
	var result = [UInt8]()
	var index = hex.startIndex

	while index < hex.endIndex {
		let next = hex.index(index, offsetBy: 2)
		result.append(UInt8(hex[index..<next], radix: 16)!)
		index = next
	}

	return result
}

private let sessionKeys = AppleRecordLayer.Keys(key: bytes(Vectors.key), iv: bytes(Vectors.iv))

/// A listener on 127.0.0.1 that hands over its first connection.
private final class ScriptedServer {
	private let listener: NWListener
	private let queue = DispatchQueue(label: "scripted-server")
	private var connection: NWConnection?
	private var accepted: CheckedContinuation<NWConnection, Never>?
	private let lock = NSLock()

	init() throws {
		let parameters = NWParameters.tcp
		parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)

		listener = try NWListener(using: parameters)
	}

	func start() async -> UInt16 {
		await withCheckedContinuation { (continuation: CheckedContinuation<UInt16, Never>) in
			listener.newConnectionHandler = { [weak self] connection in
				self?.accept(connection)
			}

			listener.stateUpdateHandler = { [listener] state in
				if case .ready = state {
					continuation.resume(returning: listener.port!.rawValue)
				}
			}

			listener.start(queue: queue)
		}
	}

	private func accept(_ connection: NWConnection) {
		connection.start(queue: queue)

		lock.lock()
		let waiter = accepted
		accepted = nil
		self.connection = connection
		lock.unlock()

		waiter?.resume(returning: connection)
	}

	func client() async -> NWConnection {
		await withCheckedContinuation { (continuation: CheckedContinuation<NWConnection, Never>) in
			lock.lock()

			if let connection {
				lock.unlock()
				continuation.resume(returning: connection)
			} else {
				accepted = continuation
				lock.unlock()
			}
		}
	}

	func stop() {
		listener.cancel()
		connection?.cancel()
	}
}

private extension NWConnection {
	func send(_ bytes: [UInt8]) async throws {
		try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
			send(content: Data(bytes), completion: .contentProcessed { error in
				if let error {
					continuation.resume(throwing: error)
				} else {
					continuation.resume()
				}
			})
		}
	}

	func receive(exactly count: Int) async throws -> [UInt8] {
		try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[UInt8], Error>) in
			receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
				if let data, data.count == count {
					continuation.resume(returning: Array(data))
				} else {
					continuation.resume(throwing: error ?? VNCError.connection(.closed))
				}
			}
		}
	}

	/// Reads one record and returns its body.
	func receiveRecord(_ opener: AppleRecordLayer.Opener) async throws -> [UInt8] {
		let header = try await receive(exactly: 2)
		let ciphertext = try await receive(exactly: Int(header[0]) << 8 | Int(header[1]))

		return try opener.open(ciphertext)
	}
}

/// Answers the login and records the states.
private final class Delegate: VNCConnectionDelegate {
	private let lock = NSLock()
	private var states = [VNCConnection.ConnectionState]()
	let disconnected: XCTestExpectation

	init(disconnected: XCTestExpectation) {
		self.disconnected = disconnected
		disconnected.assertForOverFulfill = false
	}

	var finalError: Error? {
		lock.lock()
		defer { lock.unlock() }

		return states.last?.error
	}

	func connection(_ connection: VNCConnection, stateDidChange connectionState: VNCConnection.ConnectionState) {
		lock.lock()
		states.append(connectionState)
		lock.unlock()

		if connectionState.status == .disconnected {
			disconnected.fulfill()
		}
	}

	func connection(_ connection: VNCConnection,
					credentialFor authenticationType: VNCAuthenticationType,
					completion: @escaping (VNCCredential?) -> Void) {
		completion(VNCUsernamePasswordCredential(username: "user", password: "secret"))
	}

	func connection(_ connection: VNCConnection, didCreateFramebuffer framebuffer: VNCFramebuffer) { }
	func connection(_ connection: VNCConnection, didResizeFramebuffer framebuffer: VNCFramebuffer) { }
	func connection(_ connection: VNCConnection, didUpdateFramebuffer framebuffer: VNCFramebuffer, x: UInt16, y: UInt16, width: UInt16, height: UInt16) { }
	func connection(_ connection: VNCConnection, didUpdateCursor cursor: VNCCursor) { }
}

final class AppleSessionEncryptionHandshakeTests: XCTestCase {
	private var server: ScriptedServer!

	override func tearDown() {
		server?.stop()
		server = nil
	}

	/// Connects a client to a fresh scripted server.
	private func connect(configure: (VNCConnection) -> Void = { _ in }) async throws -> (VNCConnection, Delegate, NWConnection) {
		server = try ScriptedServer()

		let port = await server.start()

		let settings = VNCConnection.Settings(isDebugLoggingEnabled: false,
											  hostname: "127.0.0.1",
											  port: port,
											  isShared: true,
											  isScalingEnabled: false,
											  useDisplayLink: false,
											  inputMode: .none,
											  isClipboardRedirectionEnabled: false,
											  colorDepth: .depth24Bit,
											  frameEncodings: [],
											  allowedAuthenticationTypes: [.appleRemoteDesktop],
											  allowsNoAuthentication: false)

		let client = VNCConnection(settings: settings, logger: VNCPrintLogger())
		let delegate = Delegate(disconnected: expectation(description: "disconnected"))

		client.delegate = delegate
		configure(client)
		client.connect()

		let peer = await server.client()

		// A client that stops sending fails the test instead of hanging it: pending receives
		// end once the connection is cancelled.
		Task {
			try await Task.sleep(nanoseconds: 15_000_000_000)

			peer.cancel()
		}

		return (client, delegate, peer)
	}

	/// The server side up to and including ServerInit. Returns the wrap key, which it checks by
	/// decrypting the credentials with it.
	private func login(_ peer: NWConnection, version: String = "RFB 003.889\n") async throws -> [UInt8] {
		try await peer.send(Array(version.utf8))
		_ = try await peer.receive(exactly: 12)

		try await peer.send([1, 30])

		let chosen = try await peer.receive(exactly: 1)
		XCTAssertEqual(chosen, [30])

		// Any odd modulus gives both sides the same secret.
		let keyLength = 64
		let prime = [0xc3] + (1..<(keyLength - 1)).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 11) } + [0x8b]
		let generator: [UInt8] = [0, 5]
		let privateKey = (0..<32).map { UInt8(truncatingIfNeeded: $0 &* 13 &+ 7) }

		let publicKey = BigNum()
		XCTAssertTrue(BigNum.modExp(y: publicKey, g: BigNum(data: Data(generator))!, x: BigNum(data: Data(privateKey))!, p: BigNum(data: Data(prime))!))

		try await peer.send(generator + [0, UInt8(keyLength)] + prime + Array(publicKey.fixedWidthBigEndianData(length: keyLength)!))

		let response = try await peer.receive(exactly: 128 + keyLength)

		let shared = BigNum()
		XCTAssertTrue(BigNum.modExp(y: shared, g: BigNum(data: Data(response[128...]))!, x: BigNum(data: Data(privateKey))!, p: BigNum(data: Data(prime))!))

		let wrapKey = AppleRecordLayer.wrapKey(diffieHellmanSharedSecret: shared.fixedWidthBigEndianData(length: keyLength)!)

		// The credentials are under the same key.
		let credentials = try stride(from: 0, to: 128, by: 16).flatMap { offset in
			try XCTUnwrap(AppleRecordCrypto.decryptBlock(Array(response[offset..<(offset + 16)]), key: wrapKey))
		}

		XCTAssertEqual(Array(credentials[0..<5]), Array("user".utf8) + [0])
		XCTAssertEqual(Array(credentials[64..<71]), Array("secret".utf8) + [0])

		try await peer.send([0, 0, 0, 0])
		_ = try await peer.receive(exactly: 1)

		// ServerInit: 64x48, 32 bpp, depth 24, little-endian true colour, name "Test".
		try await peer.send([0, 64, 0, 48] + [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0] + [0, 0, 0, 4] + Array("Test".utf8))

		return wrapKey
	}

	private func wrapped(_ block: [UInt8], key: [UInt8]) -> [UInt8] {
		// One block of CBC under a zero IV is ECB.
		AppleRecordCrypto.cbc(encrypt: true, key: key, iv: [UInt8](repeating: 0, count: 16), data: block)!
	}

	private func rekeyUpdate(wrapKey: [UInt8]) -> [UInt8] {
		[0x00, 0x00, 0x00, 0x01] + [UInt8](repeating: 0, count: 8) + [0x00, 0x00, 0x04, 0x4f] +
			[0, 0, 0, 1] + wrapped(sessionKeys.key, key: wrapKey) + wrapped(sessionKeys.iv, key: wrapKey)
	}

	private func encryptionError(_ error: Error?) -> VNCError.AppleSessionEncryptionError? {
		guard case VNCError.protocol(.appleSessionEncryption(let underlying))? = error else { return nil }

		return underlying
	}

	func testAnAppleSessionIsEncryptedAfterTheRekey() async throws {
		for pasteboard in [false, true] {
			let (client, delegate, peer) = try await connect { $0.forwardsServerClipboard = pasteboard }
			let wrapKey = try await login(peer)

			// The prelude and SetEncryption, in the clear.
			let prelude = (AppleClientMessage.prelude(pasteboard: pasteboard) + AppleClientMessage.setEncryption).flatMap { Array($0.data) }
			let clear = try await peer.receive(exactly: prelude.count)
			XCTAssertEqual(clear, prelude, "pasteboard \(pasteboard)")

			// A pasteboard notice before the key, then the key.
			try await peer.send([0x14, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02] + rekeyUpdate(wrapKey: wrapKey))

			// Everything after it comes in records: SetPixelFormat, SetEncodings, an update
			// request and, with the pasteboard, the fetch the notice asked for.
			let opener = AppleRecordLayer.Opener(keys: sessionKeys)

			var expected: [UInt8] = [0x00, 0x02, 0x03]

			if pasteboard {
				expected.append(AppleClientMessage.pasteboardFetch.messageType)
			}

			for messageType in expected {
				let body = try await peer.receiveRecord(opener)
				XCTAssertEqual(body.first, messageType, "pasteboard \(pasteboard)")
			}

			XCTAssertTrue(client.isSessionEncrypted)

			// An empty update, sealed: the client decrypts it and asks for the next one.
			let sealer = AppleRecordLayer.Sealer(keys: sessionKeys)

			try await peer.send(try sealer.seal([0, 0, 0, 0]))

			let request = try await peer.receiveRecord(opener)
			XCTAssertEqual(request.first, 0x03)

			// A damaged record ends the session.
			var damaged = try sealer.seal([0, 0, 0, 0])
			damaged[5] ^= 0x01
			try await peer.send(damaged)

			await fulfillment(of: [delegate.disconnected], timeout: 10)

			XCTAssertEqual(encryptionError(delegate.finalError), .integrityCheckFailed(sequenceNumber: 1), "\(String(describing: delegate.finalError))")

			server.stop()
		}
	}

	func testNoRekeyEndsTheSession() async throws {
		let (_, delegate, peer) = try await connect { $0.appleRekeyTimeout = 0.3 }

		_ = try await login(peer)

		await fulfillment(of: [delegate.disconnected], timeout: 10)

		XCTAssertEqual(encryptionError(delegate.finalError), .rekeyTimedOut, "\(String(describing: delegate.finalError))")
	}

	/// After ServerInit the client sends SetPixelFormat in the clear.
	private func assertClearSession(_ peer: NWConnection, client: VNCConnection, delegate: Delegate) async throws {
		let setPixelFormat = try await peer.receive(exactly: 20)

		XCTAssertEqual(setPixelFormat.first, 0x00)
		XCTAssertEqual(setPixelFormat[4], 32)
		XCTAssertFalse(client.isSessionEncrypted)

		client.disconnect()

		await fulfillment(of: [delegate.disconnected], timeout: 10)
	}

	func testTurnedOffTheSessionStaysClear() async throws {
		let (client, delegate, peer) = try await connect { $0.isAppleSessionEncryptionEnabled = false }

		_ = try await login(peer)
		try await assertClearSession(peer, client: client, delegate: delegate)
	}

	func testAServerThatIsNotApplesIsNotAsked() async throws {
		let (client, delegate, peer) = try await connect()

		_ = try await login(peer, version: "RFB 003.008\n")
		try await assertClearSession(peer, client: client, delegate: delegate)
	}
}
#endif

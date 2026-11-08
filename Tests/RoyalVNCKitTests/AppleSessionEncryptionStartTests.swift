import Foundation
import XCTest
@testable import RoyalVNCKit

// Starting session encryption: the prelude, the timeout, the rekey and what comes with it.

// MARK: - Starting encryption
final class AppleSessionEncryptionStartTests: XCTestCase {
	private let wrapKey = bytes(Vectors.wrapKey)

	/// A one-rectangle update carrying the oracle's rekey.
	private let rekeyUpdate = [0x00, 0x00, 0x00, 0x01] + [UInt8](repeating: 0, count: 8) + [0x00, 0x00, 0x04, 0x4f] + bytes(Vectors.rekey)

	private let viewerInfo = hex(Array(AppleClientMessage.viewerInfo.data))

	func testPreludeMessages() {
		XCTAssertEqual(AppleClientMessage.prelude(pasteboard: false).map { hex(Array($0.data)) },
					   [viewerInfo, "0a000001"])
		XCTAssertEqual(AppleClientMessage.prelude(pasteboard: true).map { hex(Array($0.data)) },
					   [viewerInfo, "0a000001", "1500000100000000"])
		XCTAssertEqual(AppleClientMessage.setEncryption.map { hex(Array($0.data)) },
					   ["120000010001000100000001", "1200000200010000"])
		XCTAssertEqual(viewerInfo.count, 2 * 66)
	}

	func testWrapKeyIsKeptOnlyWhenEnabledForAnAppleServer() {
		XCTAssertEqual(VNCConnection.appleRecordLayerWrapKey(wrapKey, isEnabled: true, isAppleServer: true), wrapKey)
		XCTAssertNil(VNCConnection.appleRecordLayerWrapKey(wrapKey, isEnabled: false, isAppleServer: true))
		XCTAssertNil(VNCConnection.appleRecordLayerWrapKey(wrapKey, isEnabled: true, isAppleServer: false))
	}

	func testSendsThePreludeInTheClearThenStartsTheRecordLayer() async throws {
		for pasteboard in [false, true] {
			for backend in backends {
				let connection = AppleRecordLayerNetworkConnection(base: MemoryConnection(incoming: [0x02] + rekeyUpdate))
				var timedOut = false

				let arrival = try await VNCConnection.startAppleSessionEncryption(connection: connection,
																				  wrapKey: wrapKey,
																				  pasteboard: pasteboard,
																				  timeout: 10,
																				  onTimeout: { timedOut = true },
																				  isCancelled: { false },
																				  backend: backend)

				XCTAssertEqual(arrival.rekey, .init(generation: 1, keys: keys))
				XCTAssertFalse(arrival.isPasteboardChanged)
				XCTAssertFalse(timedOut)

				let prelude = (AppleClientMessage.prelude(pasteboard: pasteboard) + AppleClientMessage.setEncryption).flatMap { Array($0.data) }

				XCTAssertEqual(hex(connection.base.written), hex(prelude), "pasteboard \(pasteboard)")
				XCTAssertTrue(connection.isRecordLayerActive)

				// The next message is a record, the oracle's first.
				try await connection.write(data: Data(bytes(Vectors.clientMessage0)))

				XCTAssertEqual(hex(Array(connection.base.written.dropFirst(prelude.count))), Vectors.clientRecord0, "\(backend)")
			}
		}
	}

	func testNoRekeyRunsTheTimeout() async {
		let base = MemoryConnection(waitsAtEnd: true)
		let connection = AppleRecordLayerNetworkConnection(base: base)
		let timedOut = expectation(description: "timeout")

		// Without the timeout, nothing would end the wait: end it here so the test fails.
		let fallback = Task {
			try await Task.sleep(nanoseconds: 5_000_000_000)

			base.cancel()
		}

		defer { fallback.cancel() }

		do {
			_ = try await VNCConnection.startAppleSessionEncryption(connection: connection,
																	wrapKey: wrapKey,
																	pasteboard: false,
																	timeout: 0.05,
																	onTimeout: {
																		timedOut.fulfill()
																		// What VNCConnection does: end the session.
																		base.cancel()
																	},
																	isCancelled: { true })
			XCTFail("no error")
		} catch { }

		await fulfillment(of: [timedOut], timeout: 5)
		XCTAssertFalse(connection.isRecordLayerActive)
	}

	func testARekeyAfterTheSessionEndedStartsNothing() async {
		let connection = AppleRecordLayerNetworkConnection(base: MemoryConnection(incoming: rekeyUpdate))

		do {
			_ = try await VNCConnection.startAppleSessionEncryption(connection: connection,
																	wrapKey: wrapKey,
																	pasteboard: false,
																	timeout: 10,
																	onTimeout: { },
																	isCancelled: { true })
			XCTFail("no error")
		} catch {
			guard case VNCError.connection(.cancelled) = error else {
				return XCTFail("\(error)")
			}
		}

		XCTAssertFalse(connection.isRecordLayerActive)
	}

	func testAPasteboardNoticeBeforeTheRekeyIsKept() async throws {
		for (command, changed) in [(UInt8(1), false), (2, true)] {
			let miscStatus: [UInt8] = [0x14, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, command]
			let connection = MemoryConnection(incoming: miscStatus + rekeyUpdate)

			let arrival = try await VNCConnection.receiveAppleRekey(connection: connection, wrapKey: wrapKey)

			XCTAssertEqual(arrival.isPasteboardChanged, changed, "command \(command)")
		}
	}

	func testAGoodRekeyCancelsTheTimeout() async throws {
		let connection = AppleRecordLayerNetworkConnection(base: MemoryConnection(incoming: rekeyUpdate))
		let timedOut = expectation(description: "no timeout")
		timedOut.isInverted = true

		_ = try await VNCConnection.startAppleSessionEncryption(connection: connection,
																wrapKey: wrapKey,
																pasteboard: false,
																timeout: 0.05,
																onTimeout: { timedOut.fulfill() },
																isCancelled: { false })

		// Well past the timeout: had the watchdog not been cancelled, it would have run.
		await fulfillment(of: [timedOut], timeout: 0.5)
	}
}

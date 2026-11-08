import XCTest
@testable import RoyalVNCKit

// Expected values come from DES implementations other than CDES: CommonCrypto with
// bit-reversed key bytes, LibVNCServer's rfbEncryptBytes and LibVNCClient's rfbClientEncryptBytes
// (VNC responses) and rfbClientEncryptBytes2 (MS-Logon II). Tests/Vectors/gen.c prints them.

private func hex(_ data: Data?) -> String? {
	data?.map { byte in
		let digits = String(byte, radix: 16)
		return byte < 0x10 ? "0" + digits : digits
	}.joined()
}

final class VNCPasswordEncryptionTests: XCTestCase {
	private let challenge = Data(0..<16)

	private func response(_ password: String) -> String? {
		hex(VNCDESEncryption.encrypt(data: challenge, key: password))
	}

	func testKnownResponses() {
		let cases: [(password: String, response: String)] = [
			("", "491e890de9ace932838a49792f2213f3"),
			("a", "449407fb6f71bd517aca76866568a4e2"),
			("1234567", "457848c96e38ad4c22e29293dee677f3"),
			("12345678", "83dd2b4dbd04367f28578fdd5b142740"),
			("123456789", "83dd2b4dbd04367f28578fdd5b142740"),
			("password", "b866924125c8eebb9debc1db61c538e2"),
			// UTF-8 c3 a9
			("é", "0c21d6b463a1339eda9ac5163528bf70"),
			// 9 UTF-8 bytes; the key is the first 8, "pässwor"
			("pässword", "c6cabacd1031f4154d399e8ae969f7c5"),
			// Byte 8 is the first byte of "é": the key is "abcdefg" + c3
			("abcdefgé", "4bbf27e0e2639d3cb3c3fec7ae01e5ab"),
			// Two 4-byte characters, exactly 8 bytes
			("😀😀", "a4663e708592524901b829550110d06e"),
			// Byte 8 is the first byte of the emoji: "abcdefg" + f0
			("abcdefg😀", "90695dcf0e3be5444dca2f4d5cff695f")
		]

		for (password, expected) in cases {
			XCTAssertEqual(response(password), expected, "password \(password.debugDescription)")
		}
	}

	func testKeyIsFirstEightUTF8Bytes() {
		XCTAssertEqual(response("123456789"), response("12345678"))
		XCTAssertEqual(response("pässword"), response("pässwor"))
		XCTAssertNotEqual(response("1234567"), response("12345678"))
	}

	func testHighBitOfEachPasswordByteIsIgnored() {
		// c3 a9 and 43 29 differ only in their high bits
		XCTAssertEqual(response("é"), response("C)"))
	}

	func testRejectsDataThatIsNotWholeBlocks() {
		for count in [0, 1, 7, 9, 15, 17] {
			XCTAssertNil(VNCDESEncryption.encrypt(data: Data(repeating: 1, count: count), key: "test"), "\(count) bytes")
		}

		for count in [8, 16, 24, 64] {
			XCTAssertEqual(VNCDESEncryption.encrypt(data: Data(repeating: 1, count: count), key: "test")?.count, count, "\(count) bytes")
		}
	}
}

final class MSLogonIIEncryptionTests: XCTestCase {
	private typealias Authentication = VNCProtocol.UltraVNCMSLogonIIAuthentication.Authentication

	private let secretKey = Data([ 0x3a, 0x91, 0xc4, 0x07, 0x5e, 0xd2, 0x68, 0xbf ])
	private let publicKey = Data([ 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78 ])

	private func authentication(secretKey: Data? = nil,
								username: String = "user",
								password: String = "secret") -> Authentication? {
		Authentication(secretKey: secretKey ?? self.secretKey,
					   publicKey: publicKey,
					   username: username,
					   password: password)
	}

	private func credential(username: String, password: String) -> Data? {
		authentication(username: username, password: password)?.encryptedCredential
	}

	// 256-byte username field then 64-byte password field, each zero-padded and encrypted
	// with DES-CBC (VNC key convention), the IV being the secret for each field.
	func testKnownCredentials() {
		let ascii = [
			"7ef6caafe52c9e0122aad309affce851681e6a0e84debe78e3de5480cd3c83ca",
			"d5ae5f613bab2c9d5a90ad52e4e0791067c4c23c72a052e21dde64115a900bc8",
			"f0311b64abc731c2fdb5f671c6499b5f11149b58a7f311eba02f2fc654ac99b8",
			"f2cde131824317d4c5ff8a4197660cd8eb10ea6c85c70cb79dea22d281a80d63",
			"e4a1ecbf75290aecd043ca1037fa709d370bbc83de3e1d5c67d9732c46d900cc",
			"c40330e2f604012748c0686c6b270d01c1bd8fef3a1011d762bd0dc3e63cfb75",
			"4858fa952486e0ec45c7226bf5b99acba7627b45fd7fe144a0376dcf8d3b28c4",
			"a69a8df90252b677e546e60aa85c74b93d36861b08b6f19b4b09727ff58317e4",
			"3cc585751dfd9054c7d53b7c54d566409d7e2aa1bb144a125b4727ee55f2d3f7",
			"fe893648e2a0fd334c24611fa659203297dcb3aa4257e41ed3dde2dde9854e2d"
		].joined()

		XCTAssertEqual(hex(credential(username: "user", password: "secret")), ascii)

		// Non-ASCII, and a 65-byte password cut to the field's 64 bytes
		let utf8 = [
			"cc3d30fa8d93bb43abc306a5dff38dd6c84a1ffaed93de941d904acdf365154b",
			"0ed87e3101223047601b3d30d4914bdcc9583763438a246036efd231b80a3587",
			"03f6f98d635a5e33fcdc34bad279f52c87fb8697ce5dce58df8c92ad2f19ea89",
			"57cd155b01089a6a9531cbd266c73534b0911ceeb292cd5cf83bc13fad00fffa",
			"ec6d9353e57cf9d1a9ea025096cdd558b7c46977f1c9cfc3f8c2cfb66538593d",
			"95154e7bca307afecfb2afca10fb0950190db3ddb35e98895dd44f7f011b3cf2",
			"f2271ae5cd38868adc44547cc0264f4622878a8623c6479572bee62894c0cfc9",
			"4f5f978fd98c14a4488b8c077c7724d0761d7b440465803e2d258bd122ea00d5",
			"9b5b733aa4d567b739feeeb50f99d6b9853ef79d730f987d5322a8b32385fcb8",
			"1cea0f1fbebf01f06fe7621a9d7a9d117da7419d59b6af4dc5464444e0723b0e"
		].joined()

		let password = Array(repeating: "pässwörd", count: 6).joined(separator: " ")

		XCTAssertEqual(hex(credential(username: "üser", password: password)), utf8)
	}

	func testPasswordFieldStartsFromTheSecretAgain() throws {
		let data = try XCTUnwrap(credential(username: "secret", password: "secret"))

		XCTAssertEqual(data.count, 320)
		XCTAssertEqual(data.subdata(in: 256..<320), data.subdata(in: 0..<64))
	}

	func testKeepsPublicKey() {
		XCTAssertEqual(authentication()?.publicKey, publicKey)
	}

	func testRejectsSecretThatIsNot8Bytes() {
		for count in [0, 7, 9, 16] {
			XCTAssertNil(authentication(secretKey: Data(repeating: 1, count: count)), "\(count) bytes")
		}
	}

	// The login path: the key agreement's shared secret encrypts, and its own public key is sent.
	func testAgreementUsesSharedSecretAndOwnPublicKey() throws {
		typealias Agreement = VNCProtocol.UltraVNCMSLogonIIAuthentication.DiffieHellmanKeyAgreement

		let generator: UInt64 = 5
		let modulus: UInt64 = 0x7fff_ffed
		let serverPrivateKey: UInt64 = 0x1234_5678
		let serverPublicKey = powMod(generator, serverPrivateKey, modulus)

		let agreement = try XCTUnwrap(Agreement(generator: bigEndian(generator),
												modulus: bigEndian(modulus),
												resp: bigEndian(serverPublicKey)))

		// The server derives the same secret from our public key
		let clientPublicKey = agreement.publicKey.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
		XCTAssertEqual(agreement.secretKey, bigEndian(powMod(clientPublicKey, serverPrivateKey, modulus)))

		let viaAgreement = try XCTUnwrap(Authentication(agreement: agreement,
														username: "user",
														password: "secret"))
		let viaSecret = try XCTUnwrap(Authentication(secretKey: agreement.secretKey,
													 publicKey: agreement.publicKey,
													 username: "user",
													 password: "secret"))

		XCTAssertEqual(viaAgreement.encryptedCredential, viaSecret.encryptedCredential)
		XCTAssertEqual(viaAgreement.publicKey, agreement.publicKey)
	}

	private func bigEndian(_ value: UInt64) -> Data {
		withUnsafeBytes(of: value.bigEndian) { Data($0) }
	}

	// Operands below 2^31, so products fit in 64 bits
	private func powMod(_ base: UInt64, _ exponent: UInt64, _ modulus: UInt64) -> UInt64 {
		var result: UInt64 = 1
		var base = base % modulus
		var exponent = exponent

		while exponent > 0 {
			if exponent & 1 == 1 {
				result = result * base % modulus
			}

			base = base * base % modulus
			exponent >>= 1
		}

		return result
	}
}

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol.ARDAuthentication {
	struct DiffieHellmanKeyAgreement {
		let publicKey: Data
		let privateKey: Data
		let secretKey: Data

		init?(prime: Data,
			  generator: Data,
			  peerKey: Data,
			  keyLength: Int) {
			// Checked before generating our key: a prime of 0 or 1 would trap or never end there
			guard keyLength > 0,
				  let bigPrime = BigNum(data: prime),
				  let bigGenerator = BigNum(data: generator),
				  let bigPeerKey = BigNum(data: peerKey),
				  bigGenerator.isValidDiffieHellmanPeerKey(prime: bigPrime),
				  bigPeerKey.isValidDiffieHellmanPeerKey(prime: bigPrime) else {
				return nil
			}

			guard let keyPair = Self.generateKeyPair(generator: generator,
													 prime: prime,
													 keyLength: keyLength),
				  !keyPair.privateKey.isEmpty,
				  !keyPair.publicKey.isEmpty else {
				return nil
			}

			guard let secretKey = Self.computeSharedKey(prime: prime,
														peerKey: peerKey,
														privateKey: keyPair.privateKey,
														keyLength: keyLength),
				  !secretKey.isEmpty else {
				return nil
			}

			self.publicKey = keyPair.publicKey
			self.privateKey = keyPair.privateKey
			self.secretKey = secretKey
		}
	}
}

private extension VNCProtocol.ARDAuthentication.DiffieHellmanKeyAgreement {
	struct KeyPair {
		let publicKey: Data
		let privateKey: Data
	}

	static func generateKeyPair(generator: Data,
								prime: Data,
								keyLength: Int) -> KeyPair? {
		let bigPrivKey = BigNum()
		let bigPubKey = BigNum()

		guard let bigPrime = BigNum(data: prime),
			  let bigGenerator = BigNum(data: generator) else {
			return nil
		}

		// Generate DH private key (a zero draw is all but impossible for a valid prime)
		var attempts = 0

		repeat {
			attempts += 1

			guard attempts <= 8,
				  bigPrivKey.rand(range: bigPrime) else {
				return nil
			}
		} while bigPrivKey.isZero

		let modSuccess = BigNum.modExp(y: bigPubKey,
									   g: bigGenerator,
									   x: bigPrivKey,
									   p: bigPrime)

		guard modSuccess else {
			return nil
		}

		// Both keys are sent and hashed as keyLength bytes, big-endian, zero-padded
		guard let privKey = bigPrivKey.fixedWidthBigEndianData(length: keyLength),
			  let pubKey = bigPubKey.fixedWidthBigEndianData(length: keyLength) else {
			return nil
		}

		let keyPair = KeyPair(publicKey: pubKey,
							  privateKey: privKey)

		return keyPair
	}

	static func computeSharedKey(prime: Data,
								 peerKey: Data,
								 privateKey: Data,
								 keyLength: Int) -> Data? {
		guard let bigPrime = BigNum(data: prime),
			  let bigPrivKey = BigNum(data: privateKey),
			  let bigPeerKey = BigNum(data: peerKey) else {
			return nil
		}

		let bigSharedKey = BigNum()

		let modSuccess = BigNum.modExp(y: bigSharedKey,
									   g: bigPeerKey,
									   x: bigPrivKey,
									   p: bigPrime)

		guard modSuccess else {
			return nil
		}

		guard let sharedKey = bigSharedKey.fixedWidthBigEndianData(length: keyLength) else {
			return nil
		}

		return sharedKey
	}
}

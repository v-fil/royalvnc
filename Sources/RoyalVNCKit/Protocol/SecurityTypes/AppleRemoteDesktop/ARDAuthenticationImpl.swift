#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(Security)
import Security
#endif

extension VNCProtocol.ARDAuthentication {
    struct Authentication {
        let cipherText: Data
        let publicKey: Data

        private init(cipherText: Data,
                     publicKey: Data) {
            self.cipherText = cipherText
            self.publicKey = publicKey
        }

        init?(agreement: DiffieHellmanKeyAgreement,
              username: String,
              password: String) {
            // Get MD5 hash of shared secret
			let secretHash = agreement.secretKey.md5Hash()

            // ciphertext: AES128(shared, username[64]:password[64])
            let credArraySize = 128
            var creds = Data(count: credArraySize)

            let randomCredsDataSuccess = creds.withUnsafeMutableBytes {
                guard let credsBytes = $0.baseAddress else { return false }

#if canImport(Security)
				let randomStatus = SecRandomCopyBytes(kSecRandomDefault, credArraySize, credsBytes)

                guard randomStatus == errSecSuccess else { return false }
#else
				// TODO: Probably not secure
				for i in 0..<credArraySize {
					$0[i] = UInt8.random(in: 0...255)
				}
#endif

                return true
            }

            guard randomCredsDataSuccess else { return nil }

			// Each field is a C string in 64 bytes: at most 63 UTF-8 bytes, then a zero.
			// Cut by bytes, not characters: a character can take up to 4 bytes.
			let maxLength = credArraySize / 2 - 1

			let usernameBytes = Array(username.utf8.prefix(maxLength))
			let passwordBytes = Array(password.utf8.prefix(maxLength))

			creds.replaceSubrange(0..<usernameBytes.count, with: usernameBytes)
			creds[usernameBytes.count] = 0

			let passwordStart = credArraySize / 2

			creds.replaceSubrange(passwordStart..<passwordStart + passwordBytes.count, with: passwordBytes)
			creds[passwordStart + passwordBytes.count] = 0

			guard let cipherText = creds.aes128ECBEncrypted(withKey: secretHash) else {
				return nil
			}

            self.init(cipherText: cipherText,
                      publicKey: agreement.publicKey)
        }
    }
}

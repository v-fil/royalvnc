#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@_implementationOnly import CDES

struct VNCDESEncryption {
	/// DES-ECB with VNC's key convention. The key is the password's first 8 UTF-8 bytes,
	/// zero-padded. Returns nil if data is empty or not a whole number of 8-byte blocks.
	static func encrypt(data: Data,
						key: String) -> Data? {
		guard !data.isEmpty, data.count.isMultiple(of: 8) else {
			return nil
		}

		var keyBytes = [UInt8](repeating: 0, count: 8)

		for (idx, byte) in key.utf8.prefix(8).enumerated() {
			keyBytes[idx] = byte
		}

		defer {
			for idx in keyBytes.indices {
				keyBytes[idx] = 0
			}
		}

		let input = [UInt8](data)
		var output = [UInt8](repeating: 0, count: input.count)

		rvnc_des_vnc_encrypt(keyBytes, input, &output, input.count / 8)

		return Data(output)
	}
}

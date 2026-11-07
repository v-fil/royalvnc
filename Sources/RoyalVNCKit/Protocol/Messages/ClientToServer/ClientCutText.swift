#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol {
	struct ClientCutText: VNCSendableMessage {
		let messageType: UInt8 = 6

		static let stringEncoding: String.Encoding = .isoLatin1

		let text: String
	}
}

extension VNCProtocol.ClientCutText {
	var data: Data {
		// Latin-1 as RFB says when the text fits it, otherwise UTF-8, which many servers
		// expect anyway; dropping the text would be worse.
		var latin1TextData = text.data(using: Self.stringEncoding) ?? Data(text.utf8)
		var textLength = latin1TextData.count

		if textLength > UInt32.max {
			textLength = .init(UInt32.max)
			latin1TextData = .init(latin1TextData.subdata(in: 0..<textLength))
		}

		let length = 8 + textLength

		var data = Data(capacity: length)

		data.append(messageType)
		data.appendPadding(length: 3)

		data.append(UInt32(textLength), bigEndian: true)
		data.append(contentsOf: latin1TextData)

		guard data.count == length else {
			fatalError("VNCProtocol.ClientCutText data.count (\(data.count)) != \(length)")
		}

		return data
	}

	func send(connection: NetworkConnectionWriting) async throws {
		try await connection.write(data: data)
	}
}

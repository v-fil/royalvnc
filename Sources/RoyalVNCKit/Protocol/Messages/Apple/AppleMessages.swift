#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@_implementationOnly import Z

// Apple Screen Sharing messages (RFB 3.889). Undocumented; the layouts follow what the
// server sends and accepts.

/// A client message given as its bytes.
struct AppleClientMessage: VNCSendableMessage {
	let data: Data

	var messageType: UInt8 { data.first ?? 0 }

	func send(connection: NetworkConnectionWriting) async throws {
		try await connection.write(data: data)
	}
}

extension AppleClientMessage {
	/// ViewerInfo (0x21). Its capability bitmap claims only the server messages the client
	/// handles: MiscStatus (0x14) and pasteboard contents (0x1f). After it the server sends
	/// MiscStatus heartbeats and pasteboard change notices.
	static let viewerInfo: Self = {
		var bytes = [UInt8](repeating: 0, count: 66)

		bytes[0] = 0x21
		bytes[3] = 62
		bytes[5] = 1

		for (offset, value) in [(6, 2), (10, 6), (14, 1), (22, 26), (26, 6), (30, 2)] {
			bytes[offset + 3] = UInt8(value)
		}

		bytes[36] = 0x08 // bit 20 (0x14), most significant bit first
		bytes[37] = 0x01 // bit 31 (0x1f)

		return .init(data: .init(bytes))
	}()

	/// SetMode (0x0a): control.
	static let setModeControl = Self(data: .init([0x0a, 0, 0, 1]))

	/// AutoPasteboard (0x15): announce pasteboard changes.
	static let autoPasteboardStart = Self(data: .init([0x15, 0, 0, 1, 0, 0, 0, 0]))

	/// Pasteboard fetch (0x0b): the server answers with pasteboard contents (0x1f).
	static let pasteboardFetch = Self(data: .init([0x0b, 0, 0, 0, 0, 0, 0, 0]))

	/// SetServerScaling (0x08): the server's screen becomes `factor` (0, 1] of its native
	/// size. Type, padding, factor as a big-endian 64-bit float.
	static func setServerScaling(_ factor: Double) -> Self {
		var bytes: [UInt8] = [0x08, 0]
		let bits = factor.bitPattern

		for shift in stride(from: 56, through: 0, by: -8) {
			bytes.append(UInt8(truncatingIfNeeded: bits >> UInt64(shift)))
		}

		return .init(data: .init(bytes))
	}

	/// Pasteboard set (0x1f): replaces the server's pasteboard with this text. Nil if it
	/// can't be compressed.
	static func pasteboardSet(text: String) -> Self? {
		let archive = ApplePasteboard.archive(text: text)

		guard let packed = ApplePasteboard.deflated(archive),
			  packed.count <= ApplePasteboard.maximumCompressedLength else {
			return nil
		}

		var bytes = [UInt8](repeating: 0, count: 16)
		bytes[0] = 0x1f

		for (index, shift) in [24, 16, 8, 0].enumerated() {
			bytes[8 + index] = UInt8(truncatingIfNeeded: archive.count >> shift)
			bytes[12 + index] = UInt8(truncatingIfNeeded: packed.count >> shift)
		}

		return .init(data: .init(bytes + packed))
	}
}

/// Apple's pasteboard archive, text only.
enum ApplePasteboard {
	static let textFlavor = "public.utf8-plain-text"

	/// Larger contents close the session rather than being read.
	static let maximumCompressedLength = 128 << 20

	/// Larger text is read and ignored.
	static let maximumTextLength = 32 << 20

	/// One item with one flavor: u32 flavor count, then per flavor a counted name, a reserved
	/// u32, a u32 count of counted key and value tags, and counted data.
	static func archive(text: String) -> [UInt8] {
		let name = Array(textFlavor.utf8)
		let data = Array(text.utf8)

		var archive: [UInt8] = []

		func put(_ value: Int) {
			for shift in [24, 16, 8, 0] {
				archive.append(UInt8(truncatingIfNeeded: value >> shift))
			}
		}

		put(1)
		put(name.count)
		archive += name
		put(0)
		put(0)
		put(data.count)
		archive += data

		return archive
	}

	/// The text flavor of the first item, if any.
	static func firstText(in archive: [UInt8]) -> String? {
		var index = 0

		func u32() -> Int? {
			guard index + 4 <= archive.count else { return nil }

			defer { index += 4 }

			return Int(archive[index]) << 24 | Int(archive[index + 1]) << 16 | Int(archive[index + 2]) << 8 | Int(archive[index + 3])
		}

		func skip(_ count: Int) -> Bool {
			guard count >= 0, index + count <= archive.count else { return false }

			index += count

			return true
		}

		guard let flavors = u32() else { return nil }

		for _ in 0..<flavors {
			guard let nameLength = u32(), index + nameLength <= archive.count else { return nil }

			let name = String(decoding: archive[index..<(index + nameLength)], as: UTF8.self)

			guard skip(nameLength), u32() != nil, let tags = u32(), tags >= 0, tags <= archive.count else { return nil }

			for _ in 0..<(tags * 2) {
				guard let length = u32(), skip(length) else { return nil }
			}

			guard let dataLength = u32(), index + dataLength <= archive.count else { return nil }

			if name == textFlavor {
				return String(decoding: archive[index..<(index + dataLength)], as: UTF8.self)
			}

			guard skip(dataLength) else { return nil }
		}

		return nil
	}

	static func deflated(_ input: [UInt8]) -> [UInt8]? {
		var stream = z_stream()

		guard deflateInit_(&stream, 9, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else { return nil }

		defer { deflateEnd(&stream) }

		var input = input
		let inputCount = input.count
		var output = [UInt8](repeating: 0, count: Int(deflateBound(&stream, UInt(inputCount))) + 64)
		let capacity = output.count

		let status: Int32 = input.withUnsafeMutableBufferPointer { inputBuffer in
			output.withUnsafeMutableBufferPointer { outputBuffer in
				stream.next_in = inputBuffer.baseAddress
				stream.avail_in = UInt32(inputCount)
				stream.next_out = outputBuffer.baseAddress
				stream.avail_out = UInt32(capacity)

				return deflate(&stream, Z_SYNC_FLUSH)
			}
		}

		guard status == Z_OK, stream.avail_in == 0 else { return nil }

		return Array(output[0..<Int(stream.total_out)])
	}

	/// At most `size` bytes inflated from a complete zlib stream.
	static func inflated(_ input: [UInt8], size: Int) -> [UInt8]? {
		var stream = z_stream()

		guard inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else { return nil }

		defer { inflateEnd(&stream) }

		var input = input
		let inputCount = input.count
		var output = [UInt8](repeating: 0, count: max(size, 1))

		let status: Int32 = input.withUnsafeMutableBufferPointer { inputBuffer in
			output.withUnsafeMutableBufferPointer { outputBuffer in
				stream.next_in = inputBuffer.baseAddress
				stream.avail_in = UInt32(inputCount)
				stream.next_out = outputBuffer.baseAddress
				stream.avail_out = UInt32(size)

				return inflate(&stream, Z_SYNC_FLUSH)
			}
		}

		guard status == Z_OK || status == Z_STREAM_END || status == Z_BUF_ERROR else { return nil }

		return Array(output[0..<Int(stream.total_out)])
	}
}

extension VNCProtocol {
	/// MiscStatus (0x14): the type byte, then `00 00 04 00 01` and a 16-bit command.
	struct AppleMiscStatus: VNCReceivableMessage {
		static let messageType: UInt8 = 0x14

		let messageType: UInt8 = Self.messageType
		let command: UInt16

		/// The server's pasteboard changed.
		var isPasteboardChanged: Bool { command == 2 }

		static func receive(connection: NetworkConnectionReading) async throws -> Self {
			let bytes = try await connection.read(length: 7)

			return .init(command: UInt16(bytes[bytes.startIndex + 5]) << 8 | UInt16(bytes[bytes.startIndex + 6]))
		}
	}

	/// Pasteboard contents (0x1f): the type byte, 15 more header bytes with the archive's
	/// inflated and compressed sizes, then the zlib-compressed archive.
	struct ApplePasteboardContents: VNCReceivableMessage {
		static let messageType: UInt8 = 0x1f

		let messageType: UInt8 = Self.messageType

		/// Nil when the archive holds no text, is damaged or too large.
		let text: String?

		static func receive(connection: NetworkConnectionReading) async throws -> Self {
			let header = Array(try await connection.read(length: 15))

			func u32(_ index: Int) -> Int {
				Int(header[index]) << 24 | Int(header[index + 1]) << 16 | Int(header[index + 2]) << 8 | Int(header[index + 3])
			}

			let plainSize = u32(7)
			let packedSize = u32(11)

			guard packedSize <= ApplePasteboard.maximumCompressedLength else {
				throw VNCError.protocol(.invalidData)
			}

			let packed = packedSize > 0
				? Array(try await connection.readBuffered(length: packedSize))
				: []

			guard packedSize > 0,
				  plainSize <= ApplePasteboard.maximumTextLength * 8,
				  let plain = ApplePasteboard.inflated(packed, size: plainSize),
				  let text = ApplePasteboard.firstText(in: plain),
				  text.utf8.count <= ApplePasteboard.maximumTextLength else {
				return .init(text: nil)
			}

			return .init(text: text)
		}
	}
}

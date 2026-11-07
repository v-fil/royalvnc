#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol {
	/// Apple encoding 1001: 4-bit greyscale. Apple Screen Sharing only.
	/// Rectangle body: 4-byte big-endian length, then zlib data. One zlib stream spans the
	/// connection, like Zlib encoding. Inflated: width * height pixels of 4 bits, high nibble
	/// first, each row starting on a byte; 0 is black, 15 white.
	struct AppleGreyEncoding: VNCFrameEncoding {
		let encodingType = VNCFrameEncodingType.appleGrey.rawValue

		let zStream: ZlibStream

		/// 4-bit grey to B, G, R, A.
		private static let palette: [UInt32] = (0..<16).map { grey in
			let value = UInt32(grey * 255 / 15)

			return 0xFF00_0000 | value << 16 | value << 8 | value
		}
	}
}

extension VNCProtocol.AppleGreyEncoding {
	func decodeRectangle(_ rectangle: VNCProtocol.Rectangle,
						 framebuffer: VNCFramebuffer,
						 connection: NetworkConnectionReading,
						 logger: VNCLogger) async throws {
		let width = Int(rectangle.width)
		let height = Int(rectangle.height)
		let bytesPerRow = (width + 1) / 2
		let packedLength = bytesPerRow * height

		let compressedData = try await VNCProtocol.ZlibEncoding.retrieveCompressedData(connection: connection,
																					   maximumUncompressedLength: packedLength,
																					   logger: logger)

		guard packedLength > 0 else { return }

		let packed: Data

		do {
			packed = try zStream.decompressedData(compressedData: compressedData,
												  uncompressedSize: UInt(packedLength))
		} catch {
			throw VNCError.protocol(.frameDecode(encodingType: encodingType, underlyingError: error))
		}

		guard packed.count == packedLength else {
			throw VNCError.protocol(.invalidData)
		}

		var pixels = Data(count: width * height * 4)

		packed.withUnsafeBytes { source in
			pixels.withUnsafeMutableBytes { destination in
				let input = source.bindMemory(to: UInt8.self)
				let output = destination.bindMemory(to: UInt32.self)
				let palette = Self.palette

				for row in 0..<height {
					let inRow = row * bytesPerRow
					let outRow = row * width

					for column in 0..<width {
						let byte = input[inRow + column / 2]
						let grey = column & 1 == 0 ? byte >> 4 : byte & 15

						output[outRow + column] = palette[Int(grey)].littleEndian
					}
				}
			}
		}

		let region = rectangle.region

		framebuffer.update(region: region,
						   internalData: &pixels)

		framebuffer.didUpdate(region: region)
	}
}

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol {
    struct ZlibEncoding: VNCFrameEncoding {
		let encodingType = VNCFrameEncodingType.zlib.rawValue

		let zStream: ZlibStream
    }
}

extension VNCProtocol.ZlibEncoding {
    func decodeRectangle(_ rectangle: VNCProtocol.Rectangle,
                         framebuffer: VNCFramebuffer,
                         connection: NetworkConnectionReading,
                         logger: VNCLogger) async throws {
        let bytesPerPixel = framebuffer.sourceProperties.bytesPerPixel

		let totalRAWBytes = rectangle.width <= 0 && rectangle.height <= 0
			? UInt(0)
			: UInt(Int(rectangle.width) * Int(rectangle.height) * bytesPerPixel)

		let compressedData = try await Self.retrieveCompressedData(connection: connection,
																   maximumUncompressedLength: Int(totalRAWBytes),
																   logger: logger)

		var data: Data

		do {
			data = try zStream.decompressedData(compressedData: compressedData,
												uncompressedSize: totalRAWBytes)

			// TODO: Not sure if it makes sense to switch to the dynamic version. Need to profile!
//			data = try zStream.decompressedData(compressedData: compressedData)
		} catch {
			throw VNCError.protocol(.frameDecode(encodingType: encodingType, underlyingError: error))
		}

        guard !data.isEmpty else {
			throw VNCError.protocol(.noData)
        }

        guard data.count == totalRAWBytes else {
			throw VNCError.protocol(.invalidData)
        }

		let region = rectangle.region

        framebuffer.update(region: region,
                           data: &data)

		framebuffer.didUpdate(region: region)
    }
}

extension VNCProtocol.ZlibEncoding {
	/// Reads a length-prefixed zlib block. Its length may not exceed what deflate needs at
	/// worst for `maximumUncompressedLength` bytes (stored blocks plus the stream header).
	static func retrieveCompressedData(connection: NetworkConnectionReading,
									   maximumUncompressedLength: Int,
									   logger: VNCLogger) async throws -> Data {
		let compressedBytesToRead = Int(try await connection.readUInt32())

		guard compressedBytesToRead <= maximumUncompressedLength + maximumUncompressedLength / 16 + 1024 else {
			throw VNCError.protocol(.invalidData)
		}

		guard compressedBytesToRead > 0 else {
			logger.logDebug("Nothing to Zlib download, skipping")

			return .init()
		}

		let chunkSize = 1024 * 16

		let compressedData = try await connection.readBuffered(length: compressedBytesToRead,
															   minimumChunkSize: 1,
															   maximumChunkSize: chunkSize)

		guard !compressedData.isEmpty else {
			throw VNCError.protocol(.noData)
		}

		guard compressedData.count == compressedBytesToRead else {
			throw VNCError.protocol(.invalidData)
		}

		return compressedData
	}
}

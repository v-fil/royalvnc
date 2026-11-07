#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@_implementationOnly import CAppleMVS

extension VNCProtocol {
	/// Apple encoding 1011 ("MVS"): 8x8 DCT tiles with a tile cache. Apple Screen Sharing only.
	/// Rectangle body: 4-byte big-endian length, then the data for the C decoder (CAppleMVS).
	/// The decoder keeps its own picture, which tile copies read from, and converts each
	/// rectangle's changed region into the framebuffer.
	final class AppleMVSEncoding: VNCFrameEncoding {
		let encodingType = VNCFrameEncodingType.appleMVS.rawValue

		private let decoder: OpaquePointer

		private var loggedProblems = 0

		init() {
			guard let decoder = mvs_new() else {
				fatalError("ERROR (Apple MVS): Failed to create decoder")
			}

			self.decoder = decoder
		}

		deinit {
			mvs_free(decoder)
		}

		/// The server's screen changed size: its tile state starts over, so the decoder's does
		/// too (picture, tile descriptors, tile cache). Quantization tables are kept.
		func reset() {
			mvs_reset(decoder)
		}
	}
}

extension VNCProtocol.AppleMVSEncoding {
	func decodeRectangle(_ rectangle: VNCProtocol.Rectangle,
						 framebuffer: VNCFramebuffer,
						 connection: NetworkConnectionReading,
						 logger: VNCLogger) async throws {
		let length = Int(try await connection.readUInt32())

		guard length <= Int(MVS_MAX_BODY) else {
			throw VNCError.protocol(.frameDecode(encodingType: encodingType,
												 underlyingError: VNCError.protocol(.invalidData)))
		}

		let body = length > 0
			? try await connection.readBuffered(length: length)
			: Data()

		let size = framebuffer.size
		var result = mvs_result()

		let code = body.withUnsafeBytes { bytes in
			mvs_decode_rect(decoder,
							Int32(size.width), Int32(size.height),
							Int32(rectangle.xPosition), Int32(rectangle.yPosition),
							Int32(rectangle.width), Int32(rectangle.height),
							bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), length,
							&result)
		}

		// Like Apple's viewer, a bad update is logged and the session carries on: what was
		// decoded before the problem is still drawn. Capped so a bad stream can't flood the log.
		if code != 0 || result.warnings != 0, loggedProblems < 20 {
			loggedProblems += 1

			let reason = String(cString: mvs_strerror(code))

			logger.logError("Apple MVS: \(reason) (\(result.warnings) warnings) for \(rectangle.region), \(length) bytes")
		}

		guard result.w > 0, result.h > 0 else { return }

		// The result lies inside the rectangle, which the update has checked against the
		// framebuffer; the blit clips to the decoder's picture.
		framebuffer.withWritableSurface { base, bytesPerRow in
			_ = mvs_blit_bgra(decoder, result.x, result.y, result.w, result.h, base, bytesPerRow)
		}

		let x = Int(result.x), y = Int(result.y)
		let width = min(Int(result.w), Int(size.width) - x)
		let height = min(Int(result.h), Int(size.height) - y)

		guard x >= 0, y >= 0, width > 0, height > 0 else { return }

		framebuffer.didUpdate(region: .init(location: .init(x: UInt16(x), y: UInt16(y)),
											size: .init(width: UInt16(width), height: UInt16(height))))
	}
}

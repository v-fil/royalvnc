#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol {
    final class ZRLEEncoding: VNCFrameEncoding {
		let encodingType = VNCFrameEncodingType.zrle.rawValue

		static let tileSize: UInt16 = 64

		let zStream: ZlibStream

		var bytesPerPixel: Int

		var pixelBuffer: Data
		var tileBuffer: Data

		init(zStream: ZlibStream) {
			self.zStream = zStream

			let bytesPerPixel = 4
			let bufferLength = Int(Self.tileSize) * Int(Self.tileSize) * bytesPerPixel

			self.bytesPerPixel = bytesPerPixel

			self.pixelBuffer = .init(repeating: 0, count: bufferLength)
			self.tileBuffer = .init(repeating: 0, count: bufferLength)
		}

		/// Little-endian true colour: 32bpp with depth 24 and every channel in the low three
		/// bytes (3-byte CPIXELs, stored as the first three bytes of the pixel), or 16bpp
		/// (CPIXEL = PIXEL). Decoded pixels stay in the source format; the framebuffer converts them.
		static func supportsPixelFormat(_ pixelFormat: VNCProtocol.PixelFormat) -> Bool {
			guard pixelFormat.trueColor,
				  !pixelFormat.bigEndian else {
				return false
			}

			switch pixelFormat.bitsPerPixel {
				case 32:
					let channels = [(pixelFormat.redMax, pixelFormat.redShift),
									(pixelFormat.greenMax, pixelFormat.greenShift),
									(pixelFormat.blueMax, pixelFormat.blueShift)]

					return pixelFormat.depth == 24 &&
						   channels.allSatisfy { (UInt32($0.0) << $0.1) < (1 << 24) }
				case 16:
					return true
				default:
					return false
			}
		}
	}
}

extension VNCProtocol.ZRLEEncoding {
	func decodeRectangle(_ rectangle: VNCProtocol.Rectangle,
						 framebuffer: VNCFramebuffer,
						 connection: NetworkConnectionReading,
						 logger: VNCLogger) async throws {
		let currentBytesPerPixel = framebuffer.sourceProperties.bytesPerPixel

		guard currentBytesPerPixel == 4 || currentBytesPerPixel == 2 else {
			throw VNCError.protocol(.zrleUnsupportedBitsPerPixel(bitsPerPixel: framebuffer.sourceProperties.bitsPerPixel))
		}

		if currentBytesPerPixel != self.bytesPerPixel {
			self.bytesPerPixel = currentBytesPerPixel

			let bufferLength = Int(Self.tileSize) * Int(Self.tileSize) * currentBytesPerPixel

			self.pixelBuffer = .init(repeating: 0, count: bufferLength)
			self.tileBuffer = .init(repeating: 0, count: bufferLength)
		}

		// Most bytes a valid rectangle can decode from: per pixel at most a CPIXEL and a run
		// length byte; per 64x64 tile a subencoding byte and a palette of up to 127 CPIXELs
		let pixelCount = Int(rectangle.width) * Int(rectangle.height)
		let tileCount = ((Int(rectangle.width) + 63) / 64) * ((Int(rectangle.height) + 63) / 64)
		let maximumLength = pixelCount * (currentBytesPerPixel + 1) + tileCount * (1 + 127 * currentBytesPerPixel)

		let compressedData = try await VNCProtocol.ZlibEncoding.retrieveCompressedData(connection: connection,
																					   maximumUncompressedLength: maximumLength,
																					   logger: logger)

		let decompressedData = try zStream.decompressedData(compressedData: compressedData,
															maximumLength: maximumLength)

		let stream = DataStream(data: decompressedData)

		// Int, so tile positions near the 65535 limit can't overflow
		let rectangleWidth = Int(rectangle.width)
		let rectangleHeight = Int(rectangle.height)

		let rectangleX = Int(rectangle.xPosition)
		let rectangleY = Int(rectangle.yPosition)

		let tileSize = Int(Self.tileSize)

        var tileY = rectangleY

        while tileY < rectangleY + rectangleHeight {
			let tileHeight = min(tileSize, rectangleY + rectangleHeight - tileY)

            var tileX = rectangleX

            while tileX < rectangleX + rectangleWidth {
				let tileWidth = min(tileSize, rectangleX + rectangleWidth - tileX)

				let actualTileSize = tileWidth * tileHeight

				let tileRegion = VNCRegion(x: .init(tileX),
										   y: .init(tileY),
										   width: .init(tileWidth),
										   height: .init(tileHeight))

//                logger.logDebug("Getting Subencoding of ZRLE Tile (Tile Region: \(tileRegion), Size: \(actualTileSize))")

				let subencoding = try stream.readUInt8()

//				logger.logDebug("Parsing ZRLE Tile Subencoding: \(subencoding))")

				if subencoding == 0 { // RAW data
					var data = try readPixels(stream: stream,
                                              logger: logger,
                                              numberOfPixels: .init(actualTileSize))

					framebuffer.update(region: tileRegion, data: &data)
				} else if subencoding == 1 { // Solid
					var background = try readPixels(stream: stream,
                                                    logger: logger,
                                                    numberOfPixels: 1)

					framebuffer.fill(region: tileRegion, withPixel: &background)
				} else if subencoding >= 2 && subencoding <= 16 {
					var data = try decodePaletteTile(stream: stream,
                                                     logger: logger,
													 paletteSize: subencoding,
													 tileSize: Self.tileSize,
													 tileWidth: .init(tileWidth),
													 tileHeight: .init(tileHeight))

					framebuffer.update(region: tileRegion, data: &data)
				} else if subencoding == 128 {
					var data = try decodeRLETile(stream: stream,
                                                 logger: logger,
												 tileSize: .init(actualTileSize))

					framebuffer.update(region: tileRegion, data: &data)
				} else if subencoding >= 130 && subencoding <= 255 {
					let paletteSize = subencoding - 128

					var data = try decodeRLEPaletteTile(stream: stream,
                                                        logger: logger,
														paletteSize: paletteSize,
														tileSize: .init(actualTileSize))

					framebuffer.update(region: tileRegion, data: &data)
				} else {
					throw VNCError.protocol(.zrleInvalidSubencoding(subencoding: subencoding))
				}

                tileX += tileSize
			}

            tileY += tileSize
		}
        
        guard stream.offset == decompressedData.count else {
            throw VNCError.protocol(.invalidData)
        }

		framebuffer.didUpdate(region: rectangle.region)
	}
}

private extension VNCProtocol.ZRLEEncoding {
	func bitsPerPixelInPalette(paletteSize: Int) -> Int {
		if paletteSize <= 2 {
			return 1
		} else if paletteSize <= 4 {
			return 2
		} else if paletteSize <= 16 {
			return 4
		}

		return 0
	}

	func readPixels(stream: AnyStream,
                    logger: VNCLogger,
					numberOfPixels: Int) throws -> Data {
//        logger.logDebug("Reading \(numberOfPixels) ZRLE pixels")

		let targetLength = numberOfPixels * bytesPerPixel

		guard bytesPerPixel == 4 else { // 16bpp: CPIXEL = PIXEL
			return try stream.read(length: targetLength)
		}

		try pixelBuffer.withUnsafeMutableBytes { pixelBufferPtr in
			let length = 3 /* RGB */ * numberOfPixels

			let buffer = try stream.read(length: length)

			var iIdx = 0
			var jIdx = 0

			let alpha: UInt8 = 255

			while iIdx < numberOfPixels * 4 {
				guard let target = pixelBufferPtr.baseAddress?.advanced(by: iIdx).assumingMemoryBound(to: UInt8.self) else {
					throw VNCError.protocol(.invalidData)
				}

				buffer.copyBytes(to: target, from: jIdx..<jIdx + 3)
				target[3] = alpha // Add Alpha

				iIdx += 4
				jIdx += 3
			}
		}

		return pixelBuffer[0..<targetLength]
	}

	func decodePaletteTile(stream: AnyStream,
                           logger: VNCLogger,
						   paletteSize: UInt8,
						   tileSize: UInt16,
						   tileWidth: UInt16,
						   tileHeight: UInt16) throws -> Data {
//        logger.logDebug("Decoding ZRLE Palette Tile (Palette Size: \(paletteSize), Tile Size: \(tileSize), Tile Width: \(tileWidth), Tile Height: \(tileWidth))")

		try tileBuffer.withUnsafeMutableBytes { tileBufferPtr in
			let palette = try readPixels(stream: stream,
										 logger: logger,
										 numberOfPixels: .init(paletteSize))

			let bitsPerPixel = bitsPerPixelInPalette(paletteSize: .init(paletteSize))
			let mask = (1 << bitsPerPixel) - 1

			var offset = 0
			var encoded = try stream.readUInt8()

			for yPos in 0..<tileHeight {
				var shift = 8 - bitsPerPixel

				for _ in 0..<tileWidth {
					if shift < 0 {
						shift = 8 - bitsPerPixel

						encoded = try stream.readUInt8()
					}

					let indexInPalette = (Int(encoded) >> shift) & mask

					guard indexInPalette < paletteSize else {
						throw VNCError.protocol(.zrlePaletteIndexOverflow(paletteIndex: indexInPalette, paletteSize: paletteSize))
					}

					let sourceStartIndex = indexInPalette * bytesPerPixel

					guard let target = tileBufferPtr.baseAddress?.advanced(by: offset).assumingMemoryBound(to: UInt8.self) else {
						throw VNCError.protocol(.invalidData)
					}

					palette.copyBytes(to: target, from: sourceStartIndex..<sourceStartIndex + bytesPerPixel)

					offset += bytesPerPixel
					shift -= bitsPerPixel
				}

				if shift < 8 - bitsPerPixel && yPos < tileHeight - 1 {
					encoded = try stream.readUInt8()
				}
			}
		}

		return tileBuffer
	}

	func decodeRLETile(stream: AnyStream,
                       logger: VNCLogger,
					   tileSize: UInt16) throws -> Data {
//        logger.logDebug("Decoding ZRLE RLE Tile (Tile Size: \(tileSize))")

		try tileBuffer.withUnsafeMutableBytes { tileBufferPtr in
			var idx = 0

			while idx < tileSize {
				let pixel = try readPixels(stream: stream,
										   logger: logger,
										   numberOfPixels: 1)

				let length = try readRLELength(stream: stream,
											   logger: logger)
                
                guard idx + length <= tileSize else {
                    throw VNCError.protocol(.invalidData)
                }

				for _ in 0..<length {
					let sourceStartIdx = idx * bytesPerPixel

					guard let target = tileBufferPtr.baseAddress?.advanced(by: sourceStartIdx).assumingMemoryBound(to: UInt8.self) else {
						throw VNCError.protocol(.invalidData)
					}

					pixel.copyBytes(to: target,
									count: bytesPerPixel)

					idx += 1
				}
			}
		}

		return tileBuffer
	}

	func decodeRLEPaletteTile(stream: AnyStream,
                              logger: VNCLogger,
							  paletteSize: UInt8,
							  tileSize: UInt16) throws -> Data {
//        logger.logDebug("Decoding ZRLE RLE Palette Tile (Palette Size: \(paletteSize), Tile Size: \(tileSize))")

		try tileBuffer.withUnsafeMutableBytes { tileBufferPtr in
			// palette
			let palette = try readPixels(stream: stream,
										 logger: logger,
										 numberOfPixels: .init(paletteSize))

			var offset = 0

			while offset < tileSize {
				var indexInPalette = Int(try stream.readUInt8())
				var length = 1

				if indexInPalette >= 128 {
					indexInPalette -= 128
					length = try readRLELength(stream: stream,
											   logger: logger)
				}

				if indexInPalette >= paletteSize {
					throw VNCError.protocol(.zrlePaletteIndexOverflow(paletteIndex: indexInPalette, paletteSize: paletteSize))
				}

				if offset + length > tileSize {
					throw VNCError.protocol(.zrlePaletteRLELengthOverflow)
				}

				for _ in 0..<length {
					let sourceStartIndex = indexInPalette * bytesPerPixel
					let targetStartIndex = offset * bytesPerPixel

					guard let target = tileBufferPtr.baseAddress?.advanced(by: targetStartIndex).assumingMemoryBound(to: UInt8.self) else {
						throw VNCError.protocol(.invalidData)
					}

					palette.copyBytes(to: target,
									  from: sourceStartIndex..<sourceStartIndex + bytesPerPixel)

					offset += 1
				}
			}
		}

		return tileBuffer
	}

	func readRLELength(stream: AnyStream,
                       logger: VNCLogger) throws -> Int {
//        logger.logDebug("Reading ZRLE RLE Length")

		var length = 0
		var current = 0

		repeat {
			current = .init(try stream.readUInt8())
			length += current
		} while (current == 255)

		return length + 1
	}
}

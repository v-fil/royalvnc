#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Framebuffer Delegate
extension VNCConnection: VNCFramebufferDelegate {
	func framebuffer(_ framebuffer: VNCFramebuffer,
					 didUpdateRegion updatedRegion: VNCRegion) {
		notifyDelegateAboutFramebuffer(framebuffer,
									   updatedRegion: updatedRegion)
	}

	func framebuffer(_ framebuffer: VNCFramebuffer,
					 didUpdateDesktopName newDesktopName: String) {
		state.desktopName = newDesktopName
	}

	func framebuffer(_ framebuffer: VNCFramebuffer,
					 didUpdateCursor cursor: VNCCursor) {
		notifyDelegateAboutUpdatedCursor(cursor)
	}

	func framebuffer(_ framebuffer: VNCFramebuffer,
					 sizeDidChange newSize: VNCSize,
					 screens newScreens: [VNCScreen]) {
		recreateFramebuffer(size: newSize,
							screens: newScreens,
							pixelFormat: framebuffer.sourcePixelFormat)

		serverScreenSizeDidChange(newSize)
	}
}

extension VNCConnection {
	func recreateFramebuffer(size: VNCSize,
							 screens: [VNCScreen],
							 pixelFormat: VNCProtocol.PixelFormat) {
		state.incrementalUpdatesEnabled = false

		let newFramebuffer: VNCFramebuffer

		do {
            newFramebuffer = try VNCFramebuffer(logger: logger,
                                                size: size,
                                                screens: screens,
                                                pixelFormat: pixelFormat,
                                                allocator: framebufferAllocator)
		} catch {
			handleBreakingError(error)

			return
		}

        // Shown until the server's next full frame replaces it.
        if let oldFramebuffer = self.framebuffer {
            newFramebuffer.copyPicture(from: oldFramebuffer)
        }

        self.framebuffer?.delegate = nil

		newFramebuffer.delegate = self

		self.framebuffer = newFramebuffer

		notifyDelegateAboutFramebufferResize(newFramebuffer)
	}
}

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A frame rectangle of a finished framebuffer update.
public struct VNCUpdatedRectangle {
	public let region: VNCRegion

	/// The rectangle's encoding, as sent by the server.
	public let encodingType: Int32
}

/// Optional callbacks besides `VNCConnectionDelegate`. Called on the connection's receive
/// task, so handlers must hop to their own thread.
public protocol VNCConnectionSessionDelegate: AnyObject {
	/// A framebuffer update message has been decoded completely: the framebuffer now holds a
	/// consistent picture. `rectangles` lists its frame rectangles (not pseudo-encodings).
	func connection(_ connection: VNCConnection,
					didFinishFramebufferUpdate framebuffer: VNCFramebuffer,
					rectangles: [VNCUpdatedRectangle])

	/// The server's clipboard changed to this text. Only when `forwardsServerClipboard` is set.
	func connection(_ connection: VNCConnection,
					didReceiveClipboardText text: String)
}

public extension VNCConnection {
	/// Counters since the connection was created. Any thread.
	struct Statistics {
		/// Bytes read from the network.
		public let bytesReceived: UInt64

		/// Time spent handling server messages, from the first byte after the message type
		/// until the message has been processed: decoding, and waiting for the rest of a
		/// message that arrives slowly. Waiting for the next message is not included.
		public let secondsHandlingMessages: Double
	}

	var statistics: Statistics {
		.init(bytesReceived: connection.bytesReceived,
			  secondsHandlingMessages: state.secondsHandlingMessages)
	}

	/// Whether the server is Apple Screen Sharing (RFB 3.889). Known after the handshake.
	var isAppleServer: Bool {
		state.isAppleRemoteDesktop
	}

	/// The size the server announced in ServerInit.
	var serverInitSize: VNCSize {
		.init(width: state.framebufferWidth,
			  height: state.framebufferHeight)
	}

	/// Sends text to the server's clipboard: Apple's pasteboard message on Apple servers
	/// (which ignore standard cut text), standard cut text elsewhere. Any thread.
	func sendClipboardText(_ text: String) {
		if isAppleServer {
			guard let message = AppleClientMessage.pasteboardSet(text: text) else {
				logger.logError("Clipboard text could not be compressed")

				return
			}

			enqueueClientToServerMessage(message)
		} else {
			enqueueClientCutTextMessage(text)
		}
	}
}

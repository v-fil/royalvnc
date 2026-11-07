#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

public extension VNCConnection {
#if canImport(ObjectiveC)
	@objc(VNCConnectionSettings)
#endif
    final class Settings: NSObjectOrAnyObject {
#if canImport(ObjectiveC)
		@objc
#endif
		public let isDebugLoggingEnabled: Bool

#if canImport(ObjectiveC)
		@objc
#endif
		public let hostname: String

#if canImport(ObjectiveC)
		@objc
#endif
		public let port: UInt16

#if canImport(ObjectiveC)
		@objc
#endif
		public let isShared: Bool

#if canImport(ObjectiveC)
		@objc
#endif
		public let isScalingEnabled: Bool

#if canImport(ObjectiveC)
		@objc
#endif
		public let useDisplayLink: Bool

#if canImport(ObjectiveC)
		@objc
#endif
		public let inputMode: InputMode

#if canImport(ObjectiveC)
		@objc
#endif
		public let isClipboardRedirectionEnabled: Bool

#if canImport(ObjectiveC)
		@objc
#endif
		public let colorDepth: ColorDepth

		public let frameEncodings: [VNCFrameEncodingType]

		/// Login types the client may use, in order of preference. The first one the server
		/// offers is chosen; if it offers none of them (and no login is not allowed), the
		/// connection fails. The order is no protection against an attacker in the network
		/// path, who can remove the preferred types from the server's offer: list only the
		/// types a host needs.
		public let allowedAuthenticationTypes: [VNCAuthenticationType]

		/// Whether a server that asks for no login is accepted, when it offers none of
		/// `allowedAuthenticationTypes`.
		public let allowsNoAuthentication: Bool

		/// Apple Remote Desktop, then VNC password.
		public static let defaultAllowedAuthenticationTypes: [VNCAuthenticationType] = [
			.appleRemoteDesktop,
			.vnc
		]

#if canImport(ObjectiveC)
		@objc(frameEncodings)
#endif
		public var _objc_frameEncodings: [Int64] {
			frameEncodings.map({ $0.rawValue.rawValue })
		}

		public init(isDebugLoggingEnabled: Bool,
					hostname: String,
					port: UInt16,
					isShared: Bool,
					isScalingEnabled: Bool,
					useDisplayLink: Bool,
					inputMode: InputMode,
					isClipboardRedirectionEnabled: Bool,
					colorDepth: ColorDepth,
					frameEncodings: [VNCFrameEncodingType],
					allowedAuthenticationTypes: [VNCAuthenticationType],
					allowsNoAuthentication: Bool) {
			self.isDebugLoggingEnabled = isDebugLoggingEnabled

			self.hostname = hostname
			self.port = port

			self.isShared = isShared

			self.isScalingEnabled = isScalingEnabled
			self.useDisplayLink = useDisplayLink

			self.inputMode = inputMode

			self.isClipboardRedirectionEnabled = isClipboardRedirectionEnabled

			self.colorDepth = colorDepth
			self.frameEncodings = frameEncodings
			self.allowedAuthenticationTypes = allowedAuthenticationTypes
			self.allowsNoAuthentication = allowsNoAuthentication
		}

		/// The default login types (`defaultAllowedAuthenticationTypes`, no login refused).
		public convenience init(isDebugLoggingEnabled: Bool,
								hostname: String,
								port: UInt16,
								isShared: Bool,
								isScalingEnabled: Bool,
								useDisplayLink: Bool,
								inputMode: InputMode,
								isClipboardRedirectionEnabled: Bool,
								colorDepth: ColorDepth,
								frameEncodings: [VNCFrameEncodingType]) {
			self.init(isDebugLoggingEnabled: isDebugLoggingEnabled,
					  hostname: hostname,
					  port: port,
					  isShared: isShared,
					  isScalingEnabled: isScalingEnabled,
					  useDisplayLink: useDisplayLink,
					  inputMode: inputMode,
					  isClipboardRedirectionEnabled: isClipboardRedirectionEnabled,
					  colorDepth: colorDepth,
					  frameEncodings: frameEncodings,
					  allowedAuthenticationTypes: Self.defaultAllowedAuthenticationTypes,
					  allowsNoAuthentication: false)
		}

#if canImport(ObjectiveC)
		@objc
#endif
		public convenience init(isDebugLoggingEnabled: Bool,
								hostname: String,
								port: UInt16,
								isShared: Bool,
								isScalingEnabled: Bool,
								useDisplayLink: Bool,
								inputMode: InputMode,
								isClipboardRedirectionEnabled: Bool,
								colorDepth: ColorDepth,
								frameEncodings: [Int64]) {
			let frameEncodingsSwift: [VNCFrameEncodingType] = frameEncodings.compactMap({
				guard let objcFrameEncodingType = _ObjC_VNCFrameEncodingType(rawValue: $0) else { return nil }

				return VNCFrameEncodingType.fromObjCFrameEncodingType(objcFrameEncodingType)
			})

			self.init(isDebugLoggingEnabled: isDebugLoggingEnabled,
					  hostname: hostname,
					  port: port,
					  isShared: isShared,
					  isScalingEnabled: isScalingEnabled,
					  useDisplayLink: useDisplayLink,
					  inputMode: inputMode,
					  isClipboardRedirectionEnabled: isClipboardRedirectionEnabled,
					  colorDepth: colorDepth,
					  frameEncodings: frameEncodingsSwift)
		}
	}
}

public extension VNCConnection.Settings {
#if canImport(ObjectiveC)
	@objc(VNCInputMode)
#endif
	enum InputMode: UInt32 {
		case none

		case forwardKeyboardShortcutsIfNotInUseLocally
		case forwardKeyboardShortcutsEvenIfInUseLocally
		case forwardAllKeyboardShortcutsAndHotKeys
	}

#if canImport(ObjectiveC)
	@objc(VNCColorDepth)
#endif
	enum ColorDepth: UInt8 {
		case depth8Bit = 8   // 256 Colors
		case depth16Bit = 16
		case depth24Bit = 24
	}
}

#if os(macOS)
public extension VNCConnection.Settings.InputMode {
	var requiresAccessibilityPermissions: Bool {
		self == .forwardAllKeyboardShortcutsAndHotKeys
	}
}

#if canImport(ObjectiveC)
@objc(VNCInputModeUtils)
#endif
// swiftlint:disable:next type_name
public final class _ObjC_VNCInputModeUtils: NSObject {
#if canImport(ObjectiveC)
	@objc
#endif
	public static func inputModeRequiresAccessibilityPermissions(_ inputMode: VNCConnection.Settings.InputMode) -> Bool {
		inputMode.requiresAccessibilityPermissions
	}
}
#endif

package mobilepkg

import "strings"

// androidPermMap maps common Android permission suffixes to canonical names.
var androidPermMap = map[string]string{
	"CAMERA":                     "camera",
	"RECORD_AUDIO":               "microphone",
	"ACCESS_FINE_LOCATION":       "location",
	"ACCESS_COARSE_LOCATION":     "location",
	"ACCESS_BACKGROUND_LOCATION": "location",
	"READ_CONTACTS":              "contacts",
	"WRITE_CONTACTS":             "contacts",
	"READ_CALENDAR":              "calendar",
	"WRITE_CALENDAR":             "calendar",
	"READ_EXTERNAL_STORAGE":      "storage",
	"WRITE_EXTERNAL_STORAGE":     "storage",
	"READ_MEDIA_IMAGES":          "photos",
	"READ_MEDIA_VIDEO":           "photos",
	"READ_PHONE_STATE":           "phone",
	"CALL_PHONE":                 "phone",
	"SEND_SMS":                   "sms",
	"RECEIVE_SMS":                "sms",
	"READ_SMS":                   "sms",
	"INTERNET":                   "network",
	"ACCESS_NETWORK_STATE":       "network",
	"ACCESS_WIFI_STATE":          "network",
	"BLUETOOTH":                  "bluetooth",
	"BLUETOOTH_ADMIN":            "bluetooth",
	"BLUETOOTH_CONNECT":          "bluetooth",
	"BLUETOOTH_SCAN":             "bluetooth",
	"BODY_SENSORS":               "sensors",
	"ACTIVITY_RECOGNITION":       "motion",
	"POST_NOTIFICATIONS":         "notifications",
	"VIBRATE":                    "haptics",
	"WAKE_LOCK":                  "background",
	"RECEIVE_BOOT_COMPLETED":     "background",
	"FOREGROUND_SERVICE":         "background",
	"USE_BIOMETRIC":              "biometrics",
	"USE_FINGERPRINT":            "biometrics",
	"NFC":                        "nfc",
}

// iosPermMap maps iOS NS*UsageDescription keys to canonical names.
var iosPermMap = map[string]string{
	"NSCameraUsageDescription":                     "camera",
	"NSMicrophoneUsageDescription":                 "microphone",
	"NSLocationWhenInUseUsageDescription":          "location",
	"NSLocationAlwaysUsageDescription":             "location",
	"NSLocationAlwaysAndWhenInUseUsageDescription": "location",
	"NSContactsUsageDescription":                   "contacts",
	"NSCalendarsUsageDescription":                  "calendar",
	"NSPhotoLibraryUsageDescription":               "photos",
	"NSPhotoLibraryAddUsageDescription":            "photos",
	"NSBluetoothAlwaysUsageDescription":            "bluetooth",
	"NSBluetoothPeripheralUsageDescription":        "bluetooth",
	"NSMotionUsageDescription":                     "motion",
	"NSSpeechRecognitionUsageDescription":          "speech",
	"NSFaceIDUsageDescription":                     "biometrics",
	"NSHealthShareUsageDescription":                "health",
	"NSHealthUpdateUsageDescription":               "health",
	"NSAppleMusicUsageDescription":                 "media",
	"NSSiriUsageDescription":                       "siri",
	"NSHomeKitUsageDescription":                    "homekit",
	"NSLocalNetworkUsageDescription":               "network",
	"NSUserTrackingUsageDescription":               "tracking",
	"NSRemindersUsageDescription":                  "reminders",
}

// canonicalPermission returns the canonical cross-platform name for an
// Android permission string (e.g. "android.permission.CAMERA" -> "camera").
func canonicalPermission(raw string) string {
	// Extract the suffix after the last dot.
	idx := strings.LastIndex(raw, ".")
	if idx < 0 {
		return ""
	}
	suffix := raw[idx+1:]
	if c, ok := androidPermMap[suffix]; ok {
		return c
	}
	return ""
}

// canonicalIOSPermission returns the canonical cross-platform name for an
// iOS permission key (e.g. "NSCameraUsageDescription" -> "camera").
func canonicalIOSPermission(raw string) string {
	if c, ok := iosPermMap[raw]; ok {
		return c
	}
	return ""
}

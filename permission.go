package mobilepkg

import "strings"

// The canonical cross-platform permission categories. Android permission
// suffixes and iOS NS*UsageDescription keys both map onto this one vocabulary,
// so naming it keeps the two tables from drifting on a typo -- "biometrics" in
// one table and "biometric" in the other would compile and silently produce two
// categories.
const (
	permCamera        = "camera"
	permMicrophone    = "microphone"
	permLocation      = "location"
	permContacts      = "contacts"
	permCalendar      = "calendar"
	permStorage       = "storage"
	permPhotos        = "photos"
	permPhone         = "phone"
	permSMS           = "sms"
	permNetwork       = "network"
	permBluetooth     = "bluetooth"
	permSensors       = "sensors"
	permMotion        = "motion"
	permNotifications = "notifications"
	permHaptics       = "haptics"
	permBackground    = "background"
	permBiometrics    = "biometrics"
	permNFC           = "nfc"
	permSpeech        = "speech"
	permHealth        = "health"
	permMedia         = "media"
	permSiri          = "siri"
	permHomeKit       = "homekit"
	permTracking      = "tracking"
	permReminders     = "reminders"
)

// androidPermMap maps common Android permission suffixes to canonical names.
var androidPermMap = map[string]string{
	"CAMERA":                     permCamera,
	"RECORD_AUDIO":               permMicrophone,
	"ACCESS_FINE_LOCATION":       permLocation,
	"ACCESS_COARSE_LOCATION":     permLocation,
	"ACCESS_BACKGROUND_LOCATION": permLocation,
	"READ_CONTACTS":              permContacts,
	"WRITE_CONTACTS":             permContacts,
	"READ_CALENDAR":              permCalendar,
	"WRITE_CALENDAR":             permCalendar,
	"READ_EXTERNAL_STORAGE":      permStorage,
	"WRITE_EXTERNAL_STORAGE":     permStorage,
	"READ_MEDIA_IMAGES":          permPhotos,
	"READ_MEDIA_VIDEO":           permPhotos,
	"READ_PHONE_STATE":           permPhone,
	"CALL_PHONE":                 permPhone,
	"SEND_SMS":                   permSMS,
	"RECEIVE_SMS":                permSMS,
	"READ_SMS":                   permSMS,
	"INTERNET":                   permNetwork,
	"ACCESS_NETWORK_STATE":       permNetwork,
	"ACCESS_WIFI_STATE":          permNetwork,
	"BLUETOOTH":                  permBluetooth,
	"BLUETOOTH_ADMIN":            permBluetooth,
	"BLUETOOTH_CONNECT":          permBluetooth,
	"BLUETOOTH_SCAN":             permBluetooth,
	"BODY_SENSORS":               permSensors,
	"ACTIVITY_RECOGNITION":       permMotion,
	"POST_NOTIFICATIONS":         permNotifications,
	"VIBRATE":                    permHaptics,
	"WAKE_LOCK":                  permBackground,
	"RECEIVE_BOOT_COMPLETED":     permBackground,
	"FOREGROUND_SERVICE":         permBackground,
	"USE_BIOMETRIC":              permBiometrics,
	"USE_FINGERPRINT":            permBiometrics,
	"NFC":                        permNFC,
}

// iosPermMap maps iOS NS*UsageDescription keys to canonical names.
var iosPermMap = map[string]string{
	"NSCameraUsageDescription":                     permCamera,
	"NSMicrophoneUsageDescription":                 permMicrophone,
	"NSLocationWhenInUseUsageDescription":          permLocation,
	"NSLocationAlwaysUsageDescription":             permLocation,
	"NSLocationAlwaysAndWhenInUseUsageDescription": permLocation,
	"NSContactsUsageDescription":                   permContacts,
	"NSCalendarsUsageDescription":                  permCalendar,
	"NSPhotoLibraryUsageDescription":               permPhotos,
	"NSPhotoLibraryAddUsageDescription":            permPhotos,
	"NSBluetoothAlwaysUsageDescription":            permBluetooth,
	"NSBluetoothPeripheralUsageDescription":        permBluetooth,
	"NSMotionUsageDescription":                     permMotion,
	"NSSpeechRecognitionUsageDescription":          permSpeech,
	"NSFaceIDUsageDescription":                     permBiometrics,
	"NSHealthShareUsageDescription":                permHealth,
	"NSHealthUpdateUsageDescription":               permHealth,
	"NSAppleMusicUsageDescription":                 permMedia,
	"NSSiriUsageDescription":                       permSiri,
	"NSHomeKitUsageDescription":                    permHomeKit,
	"NSLocalNetworkUsageDescription":               permNetwork,
	"NSUserTrackingUsageDescription":               permTracking,
	"NSRemindersUsageDescription":                  permReminders,
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

package mobilepkg_test

// TestAsAndroid and TestAsIOS are removed because asAndroid/asIOS
// are now unexported internal helpers. PlatformData access from
// external test packages uses direct type assertion on
// report.PlatformData instead.

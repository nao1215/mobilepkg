// Package ios provides iOS-specific IPA inspection logic.
// It locates and parses Info.plist and embedded entitlements from the
// Payload/<AppName>.app bundle inside the ZIP archive and normalizes
// the extracted data into the mobilepkg report model.
package ios

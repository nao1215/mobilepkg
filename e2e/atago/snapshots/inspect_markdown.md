# mobilepkg Inspection Report
## Package
| Field | Value |
|---------|---------|
| Platform | android |
| Format | apk |
| Identifier | owasp.sat.agoat |
| Display Name | AndroGoat - Insecure App (Kotlin) |
| Version | 1.0 (build 1) |
| Min SDK | 19 |

## Top Findings
> [!WARNING]  
> 9 finding(s) at warning severity or above.

| ID | Severity | Confidence | Message |
|---------|---------|---------|---------|
| exported.provider.owasp.sat.agoat.ContentProviderActivity | error | high | exported provider: owasp.sat.agoat.ContentProviderActivity (no permission required) [authorities: owasp.sat.agoat.provider.userpinsprovider] |
| exported.receiver.owasp.sat.agoat.ShowDataReceiver | warn | high | exported receiver: owasp.sat.agoat.ShowDataReceiver (no permission required) |
| exported.service.owasp.sat.agoat.DownloadInvoiceService | warn | high | exported service: owasp.sat.agoat.DownloadInvoiceService (no permission required) |
| manifest.allow_backup | warn | high | application allows backup — app data can be extracted via adb backup |
| manifest.debuggable | error | high | application is debuggable — allows arbitrary code execution via adb on any device |
| nsc.base_config_cleartext | warn | high | network security config base-config permits cleartext traffic |
| nsc.domain_cleartext. | warn | high | network security config permits cleartext traffic for:  |
| signing.debug_cert | error | high | signed with debug certificate (subject: Android Debug) — not suitable for production |
| signing.v1_only | warn | high | APK uses v1 (JAR) signing only — vulnerable to modification without invalidating signature |

## Exported Components
| Kind | Name | Required Permission | Authorities |
|---------|---------|---------|---------|
| activity | owasp.sat.agoat.AccessControl1ViewActivity |  |  |
| activity | owasp.sat.agoat.SplashActivity |  |  |
| provider | owasp.sat.agoat.ContentProviderActivity |  | owasp.sat.agoat.provider.userpinsprovider |
| receiver | androidx.profileinstaller.ProfileInstallReceiver | android.permission.DUMP |  |
| receiver | owasp.sat.agoat.ShowDataReceiver |  |  |
| service | owasp.sat.agoat.DownloadInvoiceService |  |  |

### Deep Links
| Component | URI Pattern | Actions |
|---------|---------|---------|
| owasp.sat.agoat.AccessControl1ViewActivity | androgoat://vulnapp | android.intent.action.VIEW |

<details>
<summary>Intent-filter details (6)</summary>

- **owasp.sat.agoat.AccessControl1ViewActivity** — actions: android.intent.action.VIEW, categories: android.intent.category.DEFAULT
- **owasp.sat.agoat.SplashActivity** — actions: android.intent.action.MAIN, categories: android.intent.category.LAUNCHER
- **androidx.profileinstaller.ProfileInstallReceiver** — actions: androidx.profileinstaller.action.INSTALL_PROFILE, categories: 
- **androidx.profileinstaller.ProfileInstallReceiver** — actions: androidx.profileinstaller.action.SKIP_FILE, categories: 
- **androidx.profileinstaller.ProfileInstallReceiver** — actions: androidx.profileinstaller.action.SAVE_PROFILE, categories: 
- **androidx.profileinstaller.ProfileInstallReceiver** — actions: androidx.profileinstaller.action.BENCHMARK_OPERATION, categories: 


</details>

## Network Endpoints
| Endpoint | Source | Confidence |
|---------|---------|---------|
| androgoat://vulnapp | intent_filter | high |

## Summary Metrics
| Metric | Count |
|---------|---------|
| Total findings | 15 |
| Error | 3 |
| Warning | 6 |
| Info | 6 |
| Exported components | 6 |
| Network endpoints | 1 |
| Secret candidates | 0 |
| Permissions | 7 |

<details>
<summary>Permissions (7)</summary>

| Permission | Canonical | Source |
|---------|---------|---------|
| android.permission.CAMERA | camera | manifest |
| android.permission.INTERNET | network | manifest |
| android.permission.READ_EXTERNAL_STORAGE | storage | manifest |
| android.permission.USE_BIOMETRIC | biometrics | manifest |
| android.permission.USE_FINGERPRINT | biometrics | manifest |
| android.permission.WRITE_EXTERNAL_STORAGE | storage | manifest |
| owasp.sat.agoat.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION |  | manifest |


</details>

<details>
<summary>Info-level findings (6)</summary>

| ID | Severity | Message |
|---------|---------|---------|
| exported.activity.owasp.sat.agoat.AccessControl1ViewActivity | info | exported activity: owasp.sat.agoat.AccessControl1ViewActivity (no permission required) |
| exported.activity.owasp.sat.agoat.SplashActivity | info | exported activity: owasp.sat.agoat.SplashActivity (no permission required) |
| exported.receiver.androidx.profileinstaller.ProfileInstallReceiver | info | exported receiver: androidx.profileinstaller.ProfileInstallReceiver (requires android.permission.DUMP) |
| perm.dangerous.android.permission.CAMERA | info | dangerous permission android.permission.CAMERA — can access the camera |
| perm.dangerous.android.permission.READ_EXTERNAL_STORAGE | info | dangerous permission android.permission.READ_EXTERNAL_STORAGE — can read external storage |
| perm.dangerous.android.permission.WRITE_EXTERNAL_STORAGE | info | dangerous permission android.permission.WRITE_EXTERNAL_STORAGE — can write to external storage |


</details>

<details>
<summary>Signing certificates</summary>

| Subject | Issuer | Expires | Fingerprint |
|---------|---------|---------|---------|
| Android Debug | Android Debug | <timestamp> | 0fbee68b42d0214a... |


</details>

---
Generated by mobilepkg <VERSION> (schema 1.0.0)

# mobilepkg

Android / iOS のモバイルアプリパッケージを **プラットフォームの違いを意識せずに** 解析する Go ライブラリです。

## 対応フォーマット

| フォーマット | プラットフォーム | 説明 |
|---|---|---|
| APK | Android | 標準の Android パッケージ |
| XAPK | Android | APKPure 拡張パッケージ (manifest.json + 内部 APK) |
| APKS | Android | bundletool で生成された APK セット (splits/) |
| AAB | Android | Android App Bundle (protobuf マニフェスト) |
| IPA | iOS | 標準の iOS パッケージ |

## インストール

### ライブラリとして

```bash
go get github.com/nao1215/mobilepkg
```

### CLI ツールとして

```bash
go install github.com/nao1215/mobilepkg/cmd/mobilepkg@latest
```

## ライブラリ API

API は 3 層に分かれています。

### 1. ProbeFile — 軽量なフォーマット検出

ファイルを開いて ZIP エントリを走査し、プラットフォームとフォーマットを判定します。
パッケージの中身は解析しません。

```go
result, err := mobilepkg.ProbeFile("app.apk")
if err != nil {
    log.Fatal(err)
}
fmt.Println(result.Platform) // "android"
fmt.Println(result.Format)   // "apk"
```

### 2. InspectFile — セクション選択式のレポート取得

必要な情報だけを指定して取得できます。

```go
report, err := mobilepkg.InspectFile(ctx, "app.apk", mobilepkg.InspectOptions{
    Sections: mobilepkg.SectionIdentity | mobilepkg.SectionVersion,
})
if err != nil {
    log.Fatal(err)
}
fmt.Println(report.Identity.Identifier)  // "com.example.app"
fmt.Println(report.Version.Marketing)    // "1.2.3"
```

利用可能なセクション:

| セクション | 取得できる情報 |
|---|---|
| `SectionIdentity` | パッケージ ID、表示名 |
| `SectionVersion` | マーケティングバージョン、ビルド番号 |
| `SectionEntryPoint` | メインアクティビティ (Android) / 実行ファイル (iOS) |
| `SectionPermissions` | 宣言された権限一覧 (クロスプラットフォーム正規化付き) |
| `SectionIcon` | アプリアイコン (バイナリデータ + サイズ) |
| `SectionPlatformRaw` | プラットフォーム固有の生データ (AndroidManifest / Info.plist) |
| `SectionSDK` | SDK 制約 (minSdkVersion / MinimumOSVersion) |
| `SectionSigning` | 署名・証明書情報 |
| `SectionAll` | 全セクション |

#### 権限の正規化

Android と iOS の権限名はそれぞれ異なりますが、`Permission.Canonical` フィールドで横断的に比較できます。

```go
// Android: "android.permission.CAMERA" → Canonical: "camera"
// iOS:     "NSCameraUsageDescription"   → Canonical: "camera"
```

#### プラットフォーム固有データへのアクセス

```go
if ar, ok := mobilepkg.AsAndroid(report); ok {
    fmt.Println(ar.RawManifest) // AndroidManifest の全フィールド
}
if ir, ok := mobilepkg.AsIOS(report); ok {
    fmt.Println(ir.InfoPlist)    // Info.plist の全フィールド
    fmt.Println(ir.Entitlements) // エンタイトルメント辞書
}
```

### 3. DiffReports — 2 パッケージの構造化差分

リリース前後の変更を機械的に検出します。

```go
oldReport, _ := mobilepkg.InspectFile(ctx, "v1.apk", mobilepkg.InspectOptions{})
newReport, _ := mobilepkg.InspectFile(ctx, "v2.apk", mobilepkg.InspectOptions{})

diff := mobilepkg.DiffReports(oldReport, newReport)
if diff.VersionChanged {
    fmt.Println("バージョンが変更されました")
}
for _, p := range diff.AddedPermissions {
    fmt.Printf("権限追加: %s (%s)\n", p.Canonical, p.RawName)
}
```

## CLI ツール

`mobilepkg` コマンドで全 API をコマンドラインから利用できます。出力は JSON 形式です。

### probe — フォーマット検出

```bash
$ mobilepkg probe app.apk
{
  "platform": "android",
  "format": "apk",
  "container": "zip",
  "hints": ["has AndroidManifest.xml"]
}
```

### inspect — パッケージ情報の抽出

```bash
# 全情報を取得
$ mobilepkg inspect app.apk

# 必要なセクションだけ取得
$ mobilepkg inspect -sections identity,version app.apk

# アイコンをファイルに書き出し
$ mobilepkg inspect -icon-out icon.png app.apk

# AAB のアイコンサイズを指定
$ mobilepkg inspect -icon-size 192 app.aab
```

セクション名: `identity`, `version`, `entry`, `permissions`, `icon`, `raw`, `sdk`, `signing`, `all`

### diff — 2 パッケージの差分比較

```bash
$ mobilepkg diff old.apk new.apk
{
  "old_platform": "android",
  "new_platform": "android",
  "identity_changed": false,
  "version_changed": true,
  "old_version": {"marketing": "1.0", "build": "1"},
  "new_version": {"marketing": "2.0", "build": "2"},
  "added_permissions": [
    {"canonical": "camera", "raw_name": "android.permission.CAMERA", "source": "manifest"}
  ]
}
```

## ユースケース

| シナリオ | コード例 |
|---|---|
| CI 品質ゲート | `InspectFile(ctx, apk, {Sections: SectionIdentity\|SectionVersion\|SectionPermissions})` |
| カタログ取り込み | `InspectFile(ctx, apk, {Sections: SectionIdentity\|SectionIcon})` |
| セキュリティ棚卸し | `InspectFile(ctx, apk, {Sections: SectionPermissions\|SectionPlatformRaw})` |
| リリース差分確認 | `DiffReports(oldReport, newReport)` |

## プロジェクト構成

```
mobilepkg/
├── cmd/mobilepkg/        CLI ツール
├── internal/
│   └── platform/
│       ├── android/      APK / XAPK / APKS / AAB アダプタ
│       └── ios/          IPA アダプタ
├── probe.go              フォーマット検出
├── inspect.go            レポート生成 + ルーティング
├── diff.go               構造化差分
├── types.go              公開型定義
├── permission.go         権限の正規化マッピング
└── errors.go             センチネルエラー + Diagnostic 型
```

## ライセンス

MIT License

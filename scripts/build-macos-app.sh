#!/bin/bash
set -euo pipefail

# Always build from the repository root so output paths do not depend on the current directory.
SCRIPT_DIRECTORY="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIRECTORY="$(cd "$SCRIPT_DIRECTORY/.." && pwd)"
APP_DIRECTORY="$PROJECT_DIRECTORY/dist/BareL2TP.app"

cd "$PROJECT_DIRECTORY"
cargo build --release
swift build --package-path app -c release
SWIFT_BINARY_DIRECTORY="$(swift build --package-path app -c release --show-bin-path)"

rm -rf "$APP_DIRECTORY"
mkdir -p "$APP_DIRECTORY/Contents/MacOS" "$APP_DIRECTORY/Contents/Resources"
cp app/Info.plist "$APP_DIRECTORY/Contents/Info.plist"
cp "$SWIFT_BINARY_DIRECTORY/BareL2TPApp" "$APP_DIRECTORY/Contents/MacOS/BareL2TPApp"
cp target/release/barel2tp "$APP_DIRECTORY/Contents/Resources/barel2tp"
cp app/Resources/AppIcon.icns "$APP_DIRECTORY/Contents/Resources/AppIcon.icns"
# UI localization resources must be inside the app bundle for Bundle.main to find them.
cp -R app/Resources/*.lproj "$APP_DIRECTORY/Contents/Resources/"
chmod 755 \
  "$APP_DIRECTORY/Contents/MacOS/BareL2TPApp" \
  "$APP_DIRECTORY/Contents/Resources/barel2tp"

# Local builds use an ad-hoc signature so Finder recognizes the app bundle.
codesign --force --deep --sign - "$APP_DIRECTORY"
echo "App built: $APP_DIRECTORY"

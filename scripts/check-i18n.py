#!/usr/bin/env python3
"""Checks that the macOS app's Simplified Chinese translation is complete.

UI strings use the English source text as their localization key. This script
extracts those keys from the Swift sources and compares them with
app/Resources/zh-Hans.lproj/Localizable.strings:

- a key in the source but not in the translation would show English to Chinese users
- a key in the translation but no longer in the source is most likely stale after the
  English text changed

English plural rules in app/Resources/en.lproj/Localizable.stringsdict are checked for
stale keys the same way.

Only literals passed to `L(...)` or directly to SwiftUI views that localize string
literals (`Text("...")`, `Button("...")`, ...) are treated as keys. Interpolations
become format specifiers the same way Swift does it: expressions ending in `count`
are integers (%lld), everything else is a string (%@).
"""

import plistlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "app" / "Sources" / "BareL2TPApp"
CHINESE = ROOT / "app" / "Resources" / "zh-Hans.lproj" / "Localizable.strings"
ENGLISH_PLURALS = ROOT / "app" / "Resources" / "en.lproj" / "Localizable.stringsdict"

# SwiftUI initializers and modifiers that treat a string literal as a LocalizedStringKey.
LOCALIZING_CALLS = (
    "L", "Text", "Button", "Toggle", "Section", "Label", "TextField", "SecureField",
    "LabeledContent", "CommandMenu", "Menu", "Window", ".help", ".navigationTitle",
    ".accessibilityLabel",
)
CALL = re.compile(r"(?<![\w.])(" + "|".join(re.escape(name) for name in LOCALIZING_CALLS) + r")\(\s*$")

# Brand names and technical terms that read the same in every language.
UNTRANSLATED = {"BareL2TP", "BareL2TP · %@", "VPN", "MTU", "DNS", "%@ VPN"}


def string_literals(line):
    """Returns (start, content) for each plain string literal on a line."""
    results = []
    index = 0
    while index < len(line):
        if line.startswith("//", index):
            break
        if line[index] != '"':
            index += 1
            continue
        # Raw strings #"..."# are regular expressions and similar internals, not UI text.
        raw = index > 0 and line[index - 1] == "#"
        cursor = index + 1
        depth = 0
        while cursor < len(line):
            if line.startswith("\\(", cursor):
                depth += 1
                cursor += 2
                continue
            character = line[cursor]
            if depth:
                if character == "(":
                    depth += 1
                elif character == ")":
                    depth -= 1
                elif character == '"':
                    cursor += 1
                    while line[cursor] != '"':
                        cursor += 2 if line[cursor] == "\\" else 1
            elif character == "\\":
                cursor += 1
            elif character == '"':
                break
            cursor += 1
        if not raw:
            results.append((index, line[index + 1 : cursor]))
        index = cursor + 1
    return results


def to_key(content):
    """Replaces Swift interpolations with format specifiers to get the lookup key."""
    output = []
    index = 0
    while index < len(content):
        if content.startswith("\\(", index):
            depth = 1
            cursor = index + 2
            while depth:
                if content[cursor] == "(":
                    depth += 1
                elif content[cursor] == ")":
                    depth -= 1
                cursor += 1
            expression = content[index + 2 : cursor - 1].strip()
            output.append("%lld" if re.search(r"(^|\.)count$", expression) else "%@")
            index = cursor
        else:
            output.append(content[index])
            index += 1
    return "".join(output).replace('\\"', '"')


def source_keys():
    keys = {}
    for path in sorted(SOURCES.glob("*.swift")):
        lines = path.read_text().splitlines()
        for number, line in enumerate(lines, 1):
            if line.strip().startswith("//"):
                continue
            for start, content in string_literals(line):
                before = line[:start]
                # The literal may start on the line after the opening parenthesis.
                if not before.strip() and number > 1:
                    before = lines[number - 2]
                if CALL.search(before.rstrip()) and content:
                    keys.setdefault(to_key(content), f"{path.name}:{number}")
    return keys


def translated_keys():
    text = re.sub(r"/\*.*?\*/", "", CHINESE.read_text(), flags=re.S)
    entry = re.compile(r'"((?:[^"\\]|\\.)*)"\s*=\s*"(?:[^"\\]|\\.)*"\s*;')
    return {match.group(1).replace('\\"', '"') for match in entry.finditer(text)}


def main():
    source = {key: where for key, where in source_keys().items() if key not in UNTRANSLATED}
    translated = translated_keys()
    with open(ENGLISH_PLURALS, "rb") as file:
        plurals = set(plistlib.load(file))
    missing = sorted(set(source) - translated)
    unused = sorted(translated - set(source))
    stale_plurals = sorted(plurals - set(source))
    for key in missing:
        print(f"missing Chinese translation: {key!r} ({source[key]})")
    for key in unused:
        print(f"translated key not found in the source: {key!r}")
    for key in stale_plurals:
        print(f"English plural rule for a key not found in the source: {key!r}")
    if missing or unused or stale_plurals:
        return 1
    print(f"Chinese translation complete: {len(source)} strings")
    return 0


if __name__ == "__main__":
    sys.exit(main())

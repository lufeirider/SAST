#!/usr/bin/env bash
# Build parse/tools/java-parse-ir.jar + download jp-libs/*.jar
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TOOLS="$ROOT/parse/tools"
LIBS="$TOOLS/jp-libs"
SRC="$ROOT/parse/java_parse_ir/src/main/java/sast/parse/JavaParseIr.java"
OUT_CLS="$(mktemp -d)"
BASE="${MAVEN_REPO:-https://repo1.maven.org/maven2}"

mkdir -p "$LIBS"
need=(
  "com/github/javaparser/javaparser-core/3.26.3/javaparser-core-3.26.3.jar"
  "com/github/javaparser/javaparser-symbol-solver-core/3.26.3/javaparser-symbol-solver-core-3.26.3.jar"
  "com/google/code/gson/gson/2.11.0/gson-2.11.0.jar"
  "org/javassist/javassist/3.30.2-GA/javassist-3.30.2-GA.jar"
  "com/google/guava/guava/33.2.1-jre/guava-33.2.1-jre.jar"
  "com/google/guava/failureaccess/1.0.2/failureaccess-1.0.2.jar"
  "com/google/guava/listenablefuture/9999.0-empty-to-avoid-conflict-with-guava/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar"
  "org/checkerframework/checker-qual/3.42.0/checker-qual-3.42.0.jar"
  "com/google/errorprone/error_prone_annotations/2.26.1/error_prone_annotations-2.26.1.jar"
  "com/google/j2objc/j2objc-annotations/3.0.0/j2objc-annotations-3.0.0.jar"
  "com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar"
)
for a in "${need[@]}"; do
  f="$(basename "$a")"
  if [[ -s "$LIBS/$f" ]]; then
    continue
  fi
  echo "download $f"
  curl -fsSL -o "$LIBS/$f" "$BASE/$a"
done

echo "compile JavaParseIr"
javac --release 17 -cp "$LIBS/*" -d "$OUT_CLS" "$SRC"
jar cfe "$TOOLS/java-parse-ir.jar" sast.parse.JavaParseIr -C "$OUT_CLS" .
rm -rf "$OUT_CLS"
# drop legacy jar name if present
rm -f "$TOOLS/javaparser-bridge.jar"
echo "OK -> $TOOLS/java-parse-ir.jar"

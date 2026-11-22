#!/usr/bin/env bash
# Builds chain-verify with nothing but a JDK (17+). No Gradle, no Maven, no other package of this repository.
# Produces build/chain-verify.jar, the ./verify launcher, and a signed 10,000-entry test chain in fixtures/.
set -euo pipefail
cd "$(dirname "$0")"

command -v javac >/dev/null || { echo "chain-verify: a JDK 17+ is required (javac not found)" >&2; exit 2; }

rm -rf build
mkdir -p build/classes build/fixture-classes fixtures
javac -d build/classes --release 17 $(find src/main/java -name '*.java')
jar --create --file build/chain-verify.jar --main-class io.warrant.chainverify.Main -C build/classes .

cat > verify <<'LAUNCHER'
#!/usr/bin/env bash
exec java -jar "$(dirname "$0")/build/chain-verify.jar" "$@"
LAUNCHER
chmod +x verify
printf '@echo off\r\njava -jar "%%~dp0build\chain-verify.jar" %%*\r\n' > verify.cmd

if [[ "${SKIP_FIXTURES:-0}" != "1" ]]; then
  javac -d build/fixture-classes --release 17 -cp build/classes $(find src/fixtures/java -name '*.java')
  java -cp build/classes:build/fixture-classes io.warrant.chainverify.FixtureGenerator 10000 fixtures/chain.jsonl test-public.pem 2>/dev/null \
    || java -cp "build/classes;build/fixture-classes" io.warrant.chainverify.FixtureGenerator 10000 fixtures/chain.jsonl test-public.pem
fi
echo "built build/chain-verify.jar"

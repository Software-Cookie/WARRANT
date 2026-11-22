#!/usr/bin/env bash
# Self-tests: valid chain, altered field, deleted entry, reordered entries, wrong key.
set -euo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null
mkdir -p build/test-classes
javac -d build/test-classes --release 17 -cp build/classes $(find src/test/java -name '*.java')
java -cp build/classes:build/test-classes io.warrant.chainverify.SelfTest fixtures/chain.jsonl test-public.pem 2>/dev/null \
  || java -cp "build/classes;build/test-classes" io.warrant.chainverify.SelfTest fixtures/chain.jsonl test-public.pem

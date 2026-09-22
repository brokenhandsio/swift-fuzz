#!/bin/bash
# Run on a Linux Docker host. Swift and OSS-Fuzz run in their official images.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"
results="$root/.build/oss-fuzz-validation"
mkdir -p "$results"
context=$(mktemp -d)
image="swift-fuzz-oss-validation:${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
trap 'rm -rf "$context"' EXIT

swift_image=swift:6.3.3-noble@sha256:8de8ea332a61e961ead4ef41029c2552b18e1a70dd5942d25ecf7d8de2eec5b5
docker run --rm --platform linux/amd64 --network none \
  -e CLANG_MODULE_CACHE_PATH=/tmp/swift-fuzz-clang-cache \
  -e SWIFT_MODULECACHE_PATH=/tmp/swift-fuzz-module-cache \
  --user "$(id -u):$(id -g)" -v "$root:/src/swift-fuzz" -w /src/swift-fuzz \
  "$swift_image" swift package --package-path Examples/OSSFuzzValidation \
    --cache-path /tmp/swift-fuzz-cache --config-path /tmp/swift-fuzz-config \
    --security-path /tmp/swift-fuzz-security \
    --allow-writing-to-package-directory generate-oss-fuzz-script \
    --repository https://github.com/brokenhandsio/swift-fuzz --contact ci@example.com
python3 Scripts/test-oss-fuzz-export.py Examples/OSSFuzzValidation/OSSFuzz/swift-fuzz-build.py

# Test the current checkout, including changes under review. Only tracked files
# enter the context; local corpora, notes and build directories stay on the host.
python3 - "$context" <<'PY'
from pathlib import Path
import shutil, subprocess, sys
context = Path(sys.argv[1])
for name in subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0'):
    if not name:
        continue
    source = Path(name)
    if source.is_file() or source.is_symlink():
        destination = context / 'source' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination, follow_symlinks=False)
generated = Path('Examples/OSSFuzzValidation/OSSFuzz')
for name in ('build.sh', 'swift-fuzz-build.py', 'swift-fuzz-config.json'):
    shutil.copy2(generated / name, context / name)
dockerfile = (generated / 'Dockerfile').read_text()
lines = dockerfile.splitlines()
assert sum(line.startswith('RUN git clone ') for line in lines) == 1
(context / 'Dockerfile').write_text('\n'.join(
    'COPY source /src/swift-fuzz' if line.startswith('RUN git clone ') else line
    for line in lines) + '\n')
PY
docker build --platform linux/amd64 -t "$image" "$context" > "$results/image.log" 2>&1
runner=gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04

for sanitizer in address coverage; do
  output="$results/$sanitizer"
  rm -rf "$output"
  mkdir -p "$output"
  docker run --rm --platform linux/amd64 --network none \
    -e SANITIZER="$sanitizer" -e FUZZING_LANGUAGE=swift -e ARCHITECTURE=x86_64 \
    -v "$output:/out" "$image" compile > "$results/$sanitizer-build.log" 2>&1
done

docker run --rm --platform linux/amd64 --network none \
  -e SANITIZER=address -e FUZZING_ENGINE=libfuzzer -e FUZZING_LANGUAGE=swift -e ARCHITECTURE=x86_64 \
  -v "$results/address:/out" "$runner" test_all.py > "$results/check-build.log" 2>&1

# Crash capture must work with just /out, without a Swift runtime on the bot or
# an environment variable supplied by a wrapper. Check both sync and async.
docker run --rm --platform linux/amd64 --network none \
  -e SANITIZER=address -e FUZZING_ENGINE=libfuzzer -e FUZZING_LANGUAGE=swift -e ARCHITECTURE=x86_64 \
  -v "$results/address:/out" "$runner" bash -c '
    set -euo pipefail
    cd /out
    unset SWIFT_BACKTRACE FUZZ_TARGET
    mkdir -p crash-corpus
    printf swift-fuzz-crash > crash-corpus/input
    for target in Decode AsyncDecode; do
      mkdir -p crashes/$target
      if ./$target -runs=1 -detect_leaks=0 -artifact_prefix=/out/crashes/$target/ crash-corpus > $target-crash.log 2>&1; then
        echo "Expected the synthetic crash in $target"; exit 1
      fi
      test -n "$(find crashes/$target -name "crash-*" -type f -print -quit)"
    done
  '

# Prepare a corpus from the exported archives; duplicate source basenames must
# retain both distinct inputs. The target without seeds exercises an empty input.
python3 - "$results" <<'PY'
from pathlib import Path
import json, sys, zipfile
root = Path(sys.argv[1])
output = root / 'coverage'
manifest = json.loads((output / 'swift-fuzz-targets.json').read_text())
assert {(entry['product'], entry['target']) for entry in manifest} == {
    ('Combined', 'Decode'), ('Combined', 'AsyncDecode'), ('OtherProduct', 'Single')}
for entry in manifest:
    target = entry['target']
    corpus = root / 'corpus' / target
    corpus.mkdir(parents=True, exist_ok=True)
    archive = output / (target + '_seed_corpus.zip')
    if archive.exists():
        with zipfile.ZipFile(archive) as seeds:
            if target == 'Decode':
                assert len(seeds.namelist()) == 2
            seeds.extractall(corpus)
    else:
        (corpus / 'empty').write_bytes(b'')
PY
docker run --rm --platform linux/amd64 --network none \
  -e SANITIZER=coverage -e FUZZING_ENGINE=libfuzzer -e FUZZING_LANGUAGE=swift \
  -e ARCHITECTURE=x86_64 -e COVERAGE_EXTRA_ARGS= \
  -v "$results/coverage:/out" -v "$results/corpus:/corpus" \
  "$runner" coverage > "$results/coverage-run.log" 2>&1
python3 - "$results/coverage" <<'PY'
from pathlib import Path
import json, sys
output = Path(sys.argv[1])
for target in ('Decode', 'AsyncDecode', 'Single'):
    assert not (output / 'fuzzer_stats' / (target + '_error.log')).exists(), target
    report = json.loads((output / 'fuzzer_stats' / (target + '.json')).read_text())
    files = [file for data in report['data'] for file in data['files']]
    harnesses = [file for file in files if '/OSSFuzzValidation/Targets/' in file['filename'] and file['filename'].endswith('Harness.swift')]
    assert any(file['summary']['lines']['covered'] > 0 for file in harnesses), target
    assert (output / 'report_target' / target / 'linux' / 'index.html').is_file(), target
print('OSS-Fuzz native exports, crashes, seeds, resources and source coverage passed.')
PY

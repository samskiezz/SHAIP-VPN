#!/usr/bin/env bash
# Builds the iPhone app preview into clients/ios/preview/dist/index.html: one
# self-contained page (no network requests) made of
#   page.html                 markup and styles
#   ../design/shaip-engine.js the design's render engine, unchanged but for its
#                             one `export`, so the page draws exactly what the
#                             iPhone renderer is tested against
#   sample-client.toml        a well-formed client config for "Use a sample server"
#   app.js                    the app's screens and the simulated session
# dist/local.html is the same page wrapped in a document, for opening directly.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf dist && mkdir -p dist

python3 -I - <<'PY'
import json, re
engine = open("../design/shaip-engine.js").read()
exports = re.findall(r"^export\s", engine, flags=re.M)
assert len(exports) == 1, "expected exactly one export in shaip-engine.js"
engine = re.sub(r"^export\s+function draw", "function draw", engine, flags=re.M)
sample = open("sample-client.toml").read()
app = open("app.js").read()
bundle = "\n".join([
    "// ---- clients/ios/design/shaip-engine.js ----", engine,
    "// ---- clients/ios/preview/sample-client.toml ----", "const SAMPLE_CONFIG = " + json.dumps(sample) + ";",
    "// ---- clients/ios/preview/app.js ----", app,
])
assert "</script" not in bundle.lower()
page = open("page.html").read()
assert page.count("/*__BUNDLE__*/") == 1
page = page.replace("/*__BUNDLE__*/", bundle)
open("dist/index.html", "w").write(page)
open("dist/local.html", "w").write(
    '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"></head><body>\n'
    + page + "\n</body></html>\n")
PY
ls -la dist

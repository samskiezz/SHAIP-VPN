#!/usr/bin/env bash
# Builds the hosted web preview into web-ui/preview/dist:
#   index.html      the real pages (web-ui/pages) bundled, with React from
#                   cdnjs, Tailwind compiled, and Go's wasm_exec.js inlined
#   pqanon-cp.wasm  the real control plane (control-plane/wasm_main.go)
# The page is a single-page shell over the same components the Next.js app
# serves; its API calls go to the control plane running in the tab.
set -euo pipefail
cd "$(dirname "$0")"
OUT=dist
rm -rf "$OUT" && mkdir -p "$OUT"

( cd ../../control-plane &&
  GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o ../web-ui/preview/$OUT/pqanon-cp.wasm . &&
  cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" ../web-ui/preview/$OUT/wasm_exec.js )

npx --yes esbuild@0.23.1 main.tsx --bundle --minify --format=iife --target=es2019 \
  --jsx=transform --jsx-factory=React.createElement --jsx-fragment=React.Fragment \
  --alias:react=./shims/react.js --alias:react-dom/client=./shims/react-dom-client.js \
  --alias:next/router=./shims/next-router.tsx --alias:next/link=./shims/next-link.tsx \
  '--define:process.env.NEXT_PUBLIC_API_URL=""' --log-level=warning --outfile="$OUT/app.js"

../node_modules/.bin/tailwindcss -c ../tailwind.config.js -i ../styles/globals.css \
  --content '../pages/**/*.tsx,../components/**/*.tsx,./**/*.tsx' --minify -o "$OUT/app.css" 2>/dev/null

python3 - "$OUT" <<'PY'
import sys
out = sys.argv[1]
page = open("page.html").read()
css = open(f"{out}/app.css").read().replace(":root{color-scheme:light dark}", "")
for marker, path, text in [("/*__TAILWIND__*/", None, css),
                           ("/*__WASM_EXEC__*/", f"{out}/wasm_exec.js", None),
                           ("/*__APP__*/", f"{out}/app.js", None)]:
    body = text if text is not None else open(path).read()
    assert "</script" not in body.lower() or marker == "/*__TAILWIND__*/", marker
    page = page.replace(marker, body)
open(f"{out}/index.html", "w").write(page)
PY
rm -f "$OUT/app.js" "$OUT/app.css" "$OUT/wasm_exec.js"
ls -la "$OUT"

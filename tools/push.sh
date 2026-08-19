#!/usr/bin/env bash
# Push a file straight to GitHub main. Survives container resets — this repo is the only durable store.
# Usage:  GH=<token> bash tools/push.sh <local-path> <repo-path> "<commit message>"
# Repo paths containing [ ] must be percent-encoded, e.g. functions/api/room/%5Bcode%5D.js
set -euo pipefail
R=hrachyajavadyan/assay
LOCAL="$1"; ENC="$2"; MSG="${3:-update}"
[ -z "${GH:-}" ] && { echo "GH env var (token) not set"; exit 1; }
SHA=$(curl -s --noproxy '*' -H "Authorization: Bearer $GH" \
  "https://api.github.com/repos/$R/contents/$ENC?ref=main" \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('sha','') if isinstance(d,dict) else '')")
python3 - "$LOCAL" "$SHA" "$MSG" <<'PY'
import base64,json,sys
local,sha,msg=sys.argv[1],sys.argv[2],sys.argv[3]
p={'message':msg,'content':base64.b64encode(open(local,'rb').read()).decode(),'branch':'main'}
if sha: p['sha']=sha
json.dump(p,open('/tmp/_push.json','w'))
PY
curl -s --noproxy '*' -X PUT -H "Authorization: Bearer $GH" -H "Accept: application/vnd.github+json" \
  -H "Content-Type: application/json" --data @/tmp/_push.json \
  "https://api.github.com/repos/$R/contents/$ENC" \
  | python3 -c "import sys,json;j=json.load(sys.stdin);print('pushed',j['commit']['sha'][:8]) if 'commit' in j else (print('ERROR',json.dumps(j)[:300]),sys.exit(1))"

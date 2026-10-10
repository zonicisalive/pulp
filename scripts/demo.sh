#!/bin/sh
# Builds a throw-away sandbox full of FAKE misconfigurations and runs pulp against it.
# Nothing here touches your real home directory. Usage: scripts/demo.sh [path-to-pulp]
set -eu
PULP=${1:-./pulp}
PULP=$(cd "$(dirname "$PULP")" && pwd)/$(basename "$PULP")
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
H=$T/home APP=$T/shop-api
mkdir -p "$H/.ssh" "$H/.aws" "$APP/.github/workflows"
chmod 755 "$H"

# ---- fake laptop ----
ssh-keygen -q -t ed25519 -N "" -f "$H/.ssh/id_ed25519" && chmod 644 "$H/.ssh/id_ed25519"
printf '[default]\naws_access_key_id = AKIAXXXXXXXXXXXXXXXX\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYexamplekey\n' > "$H/.aws/credentials"
chmod 644 "$H/.aws/credentials"
# fake token assembled at runtime so this file itself never contains a token-shaped string
printf 'ls\nexport DB_PASSWORD=hunter2hunter2\ngh auth login --with-token %s%s\n' ghp_ 1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R > "$H/.bash_history"
printf '[credential]\n\thelper = store\n' > "$H/.gitconfig"

# ---- fake project ----
cd "$APP"
git init -q
git config user.email demo@example.com; git config user.name demo
printf 'KEY=%s%s\n' AKIA QWERTYUIOP12345X > config.txt        # a "real-looking" key, committed then removed
git add -A; git commit -q -m "add config"; git rm -q config.txt; git commit -q -m "remove config"
cat > docker-compose.yml <<'EOF'
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"
  agent:
    image: example/agent
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
EOF
printf 'from flask import Flask\napp = Flask(__name__)\napp.run(host="0.0.0.0", debug=True)\n' > server.py
printf 'const cors = require("cors");\napp.use(cors({ origin: "*", credentials: true }));\n' > app.js
printf 'FROM node:latest\nRUN curl -sSL https://example.com/install.sh | sh\nCMD ["node", "app.js"]\n' > Dockerfile
cat > .github/workflows/ci.yml <<'EOF'
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: someone/deploy-action@v1
      - run: echo "${{ github.event.pull_request.title }}"
EOF
printf 'DB_URL=postgres://app:password@localhost/shop\n' > .env

# ---- run ----
export HOME=$H XDG_CONFIG_HOME=$T/cfg
"$PULP" scan --color always --format short "$APP" || true

#!/usr/bin/env bash
set -euo pipefail

templates_dir="${NUCLEI_TEMPLATES_DIR:-/opt/nuclei-templates}"
missing=0

for tool in testssl.sh nikto nuclei nmap zap-baseline.py; do
    if command -v "${tool}" >/dev/null 2>&1; then
        echo "[zircon-runtime] ${tool}: $(command -v "${tool}")"
    else
        echo "[zircon-runtime] missing required scanner tool: ${tool}" >&2
        missing=1
    fi
done

if [ -d "${templates_dir}" ]; then
    template_count="$(find "${templates_dir}" -type f | wc -l | tr -d ' ')"
    echo "[zircon-runtime] nuclei templates: ${templates_dir} (${template_count} files)"
else
    echo "[zircon-runtime] nuclei templates directory missing: ${templates_dir}" >&2
    missing=1
fi

exit "${missing}"

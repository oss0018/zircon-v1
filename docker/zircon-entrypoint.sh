#!/usr/bin/env bash
set -euo pipefail

templates_dir="${NUCLEI_TEMPLATES_DIR:-/opt/nuclei-templates}"
mkdir -p "${templates_dir}"

if command -v nuclei >/dev/null 2>&1 && [ "${ZIRCON_NUCLEI_UPDATE_TEMPLATES:-1}" = "1" ]; then
    if [ -z "$(find "${templates_dir}" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
        echo "[zircon-runtime] Bootstrapping nuclei templates into ${templates_dir}"
        if ! nuclei -update-templates -update-template-dir "${templates_dir}"; then
            echo "[zircon-runtime] WARNING: nuclei template update failed; continue with manual or later template sync"
        fi
    fi
fi

verify-vuln-tools
exec "$@"

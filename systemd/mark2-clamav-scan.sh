#!/bin/sh
# mark2-clamav-scan.sh — runs the ClamAV subgraph as a background scan of the
# HOST's high-risk directories, via a throwaway `docker run` of the mark2 image.
#
# Why this exists: `docker run mark2` (the main diagnostic container) never
# scans for malware itself — agent.py's "malware" stage only reads whatever
# this script last wrote (tools.get_last_malware_result / clamav_parser.
# save_last_result). A full ClamAV scan can take 1-4+ hours, so it runs here,
# out-of-band, on its own schedule (see mark2-clamav-scan.timer), not inside
# the request path of a diagnostic run.
#
# Bind mounts explained:
#   - The high-risk dirs (_DEFAULT_SCAN_PATHS in clamav_parser.py) are mounted
#     read-only: clamscan only ever reads file content, never needs to write.
#   - /var/lib/clamav is mounted read-write so freshclam's downloaded
#     definitions persist across --rm runs instead of re-downloading ~200MB+
#     every single invocation (clamav_parser._definitions_are_fresh already
#     skips freshclam if defs are <24h old, but that check is useless if the
#     directory it's checking is wiped every run).
#   - clamav_manifest.db is bind-mounted to a persistent host path so the
#     incremental-scan manifest AND the last-completed-result cache survive
#     across runs — this is the file agent.py's containers ultimately read
#     from (also bind-mount it into those containers if they run in Docker
#     too, with -v "$STATE_DIR/clamav_manifest.db:/clamav_manifest.db").
#
# Env overrides:
#   MARK2_IMAGE      Docker image tag to run                  (default: mark2)
#   MARK2_STATE_DIR  Host dir holding the persistent manifest  (default: /var/lib/mark2)

set -eu

IMAGE="${MARK2_IMAGE:-mark2}"
STATE_DIR="${MARK2_STATE_DIR:-/var/lib/mark2}"

mkdir -p "$STATE_DIR"
touch "$STATE_DIR/clamav_manifest.db"
mkdir -p /var/lib/clamav

exec docker run --rm \
    --entrypoint /venv/bin/python3 \
    -v /home:/home:ro \
    -v /tmp:/tmp:ro \
    -v /var/tmp:/var/tmp:ro \
    -v /opt:/opt:ro \
    -v /srv:/srv:ro \
    -v /root:/root:ro \
    -v /var/www:/var/www:ro \
    -v /var/lib/clamav:/var/lib/clamav \
    -v "$STATE_DIR/clamav_manifest.db:/clamav_manifest.db" \
    -e CLAMAV_MANIFEST_DB=/clamav_manifest.db \
    "$IMAGE" -m scanners.clamav.clamav_subgraph

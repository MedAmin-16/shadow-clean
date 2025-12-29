#!/bin/bash
# ShadowTwin Scan Cleanup - Manage RAM & Kill Stalled Processes
echo "[CLEANUP] Starting scan cleanup..."
# Kill processes over 2 hours old
ps aux | awk '$9 ~ /[0-9]+:[0-9]+h/ {print $2}' | xargs -r kill -9 2>/dev/null
# Clear tmp files
rm -rf /tmp/nuclei-* /tmp/ffuf-* /tmp/commix-* 2>/dev/null
# Free memory buffers
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
echo "[CLEANUP] Cleanup complete"

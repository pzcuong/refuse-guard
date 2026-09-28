#!/bin/zsh
# Round-16 Kaggle poller: status every 5 min; auto-downloads outputs on
# completion. Logs to outputs/packguard/r16_kaggle/monitor.log. Safe to
# re-run (download markers prevent duplicates).
export PATH="$HOME/.local/bin:$PATH"
OUT=/Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/r16_kaggle
mkdir -p "$OUT"
echo "$(date -u +%FT%TZ) poller start" >> "$OUT/monitor.log"
for i in $(seq 1 240); do
  for slug in packguard-p110-p18 packguard-p110-llama8b; do
    st=$(kaggle kernels status "pzcuong/$slug" 2>&1)
    echo "$(date -u +%FT%TZ) $slug $st" >> "$OUT/monitor.log"
    if [[ "$st" == *COMPLETE* || "$st" == *ERROR* || "$st" == *CANCEL* ]]; then
      if [ ! -f "$OUT/.downloaded_$slug" ]; then
        mkdir -p "$OUT/$slug"
        echo "$(date -u +%FT%TZ) downloading output of $slug" >> "$OUT/monitor.log"
        kaggle kernels output "pzcuong/$slug" -p "$OUT/$slug" >> "$OUT/monitor.log" 2>&1
        touch "$OUT/.downloaded_$slug"
      fi
    fi
  done
  if [ -f "$OUT/.downloaded_packguard-p110-p18" ] && [ -f "$OUT/.downloaded_packguard-p110-llama8b" ]; then
    echo "$(date -u +%FT%TZ) both outputs downloaded - poller exits" >> "$OUT/monitor.log"
    exit 0
  fi
  sleep 300
done
echo "$(date -u +%FT%TZ) poller max iterations reached" >> "$OUT/monitor.log"

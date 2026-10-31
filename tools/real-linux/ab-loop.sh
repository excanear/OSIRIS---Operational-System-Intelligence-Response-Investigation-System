#!/usr/bin/env bash
# TEMPORARY (branch real-linux/t11b4-ab only, never merged): A/B of
# dns_query_is_observed_and_alerts with the filesystem sensor on/off,
# interleaved. Runs as root from the workflow. Usage: ab-loop.sh <N> <out>
set -uo pipefail
n=$1; out=$2
on_pass=0; on_fail=0; off_pass=0; off_fail=0
rm -f /tmp/osiris-ab-fs-off-*
for i in $(seq 1 "$n"); do
  for arm in on off; do
    log="$out/ab-$arm-$i.txt"
    if [ "$arm" = off ]; then
      before=$(ls /tmp/osiris-ab-fs-off-* 2>/dev/null | wc -l)
      OSIRIS_AB_NO_FS=1 tools/real-linux/run.sh dns_query_is_observed_and_alerts --exact --nocapture >"$log" 2>&1
      after=$(ls /tmp/osiris-ab-fs-off-* 2>/dev/null | wc -l)
      [ "$after" -gt "$before" ] || echo "::error title=A/B arm off run $i::filesystem sensor was NOT disabled (no marker)"
    else
      env -u OSIRIS_AB_NO_FS tools/real-linux/run.sh dns_query_is_observed_and_alerts --exact --nocapture >"$log" 2>&1
    fi
    if grep -q "test result: ok. 1 passed" "$log"; then r=PASS; eval "${arm}_pass=\$((${arm}_pass+1))"
    else r=FAIL; eval "${arm}_fail=\$((${arm}_fail+1))"
      msg=$(grep -E "panicked at|never matched|assert" "$log" | head -2 | cut -c1-400 | tr '\n' ' ')
      echo "::warning title=A/B fs_$arm run $i FAIL::$msg"
    fi
    echo "fs_$arm run $i: $r"
  done
done
summary="fs_on: $on_pass pass / $on_fail fail; fs_off: $off_pass pass / $off_fail fail (n=$n each, interleaved)"
echo "$summary"
echo "::notice title=A/B result::$summary"

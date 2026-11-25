#!/usr/bin/env bash
# Wait (up to $1 seconds, default 540) for rebuild.sh to finish, then summarize.
limit="${1:-540}"
for _ in $(seq 1 $((limit / 5))); do
  [ -f /root/st-build.done ] && break
  sleep 5
done
if [ ! -f /root/st-build.done ]; then
  echo "STATUS: still running"
  tail -n 5 /root/st-build.log
  exit 0
fi
echo "STATUS: exit $(cat /root/st-build.done)"
grep -E '\.go:[0-9]+:[0-9]+|^.{0,12}(FAIL|ok )|go: |makensis|Error in script|error:' /root/st-build.log | grep -v 'go: downloading' | head -60
echo "--- tail"
tail -n 12 /root/st-build.log

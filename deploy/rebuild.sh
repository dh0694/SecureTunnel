#!/usr/bin/env bash
# Rebuild the image in the background and record the result.
#   ./rebuild.sh           build only (current containers keep running)
#   ./rebuild.sh --up      build, then restart the stack on the new image
# Progress: /root/st-build.log   Result: /root/st-build.done (exit code)
#
# Each build gets a new agent version, 1.<day of year>.<minute of day> (UTC),
# so installed agents see it as newer and update themselves.
cd "$(dirname "$0")"
rm -f /root/st-build.done
UP="${1:-}"
DAY=$((10#$(date -u +%j)))
MIN=$(( 10#$(date -u +%H) * 60 + 10#$(date -u +%M) ))
VERSION="1.${DAY}.${MIN}"
echo "$VERSION" > /root/st-build.version
nohup sh -c "docker compose build --build-arg VERSION=$VERSION control > /root/st-build.log 2>&1; rc=\$?; if [ \$rc -eq 0 ] && [ '$UP' = '--up' ]; then docker compose up -d >> /root/st-build.log 2>&1; rc=\$?; fi; echo \$rc > /root/st-build.done" > /dev/null 2>&1 &
echo "build started (version $VERSION)"

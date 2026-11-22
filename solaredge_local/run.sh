#!/usr/bin/with-contenv bashio
cd /opt/solaredge_local || exit 1
exec python3 -m app.main --options /data/options.json --data-dir /data

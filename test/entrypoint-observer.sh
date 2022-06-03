#!/bin/bash

set -e -u

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Start rsyslog. Note: Sometimes for unknown reasons /var/run/rsyslogd.pid is
# already present, which prevents the whole container from starting. We remove
# it just in case it's there.
rm -f /var/run/rsyslogd.pid
service rsyslog start

# make sure we can reach the wfe.
./test/wait-for-it.sh boulder 4001

if [[ $# -eq 0 ]]; then
    ./bin/boulder-observer -config ${BOULDER_CONFIG_DIR}/observer.yml
fi

exec "$@"

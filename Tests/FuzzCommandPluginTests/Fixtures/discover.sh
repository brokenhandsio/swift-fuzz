#!/bin/sh
set -eu
cat "$0.stdout"
exit "$(cat "$0.status")"

#!/bin/sh
set -eu
echo "$*" >> arguments
merge=0
destination=
for arg in "$@"; do
  case "$arg" in
    -merge=1) merge=1 ;;
    -merge=0) merge=0 ;;
    -*) ;;
    *) if [ -z "$destination" ]; then destination="$arg"; fi ;;
  esac
done
if [ "$merge" = 1 ]; then
  cp Seeds/Probe/seed "$destination/selected"
  touch merged
  exit "$(cat merge-status)"
fi
if [ -f merged ]; then
  . ./candidate.sh
else
  echo '#2 DONE cov: 10 ft: 20' >&2
fi

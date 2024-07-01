#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [ -z ${1+x} ]; then
  VERSION="0.0.0"
else
  VERSION="$1"
fi

mkdir -p "$SCRIPT_DIR/dist"
rm "$SCRIPT_DIR"/dist/* &> /dev/null

BUILDARGS="$(uname)-$(uname -p)"
OUTPUTFILE="$SCRIPT_DIR/dist/freematics-encrypt-$VERSION-$BUILDARGS"

cd "$SCRIPT_DIR/src" || exit 1
go mod tidy
go build -v -trimpath -ldflags "-s -w -X main.VersionDate=$(date -u --iso-8601=minutes) -X main.Version=v$VERSION" -o "$OUTPUTFILE"

if [ $? -eq 0 ]; then
  chmod +x "$OUTPUTFILE"
  echo "Build Succeeded ->  $OUTPUTFILE"
fi

#!/bin/bash

set -x

mkdir -p bin

export GOOS=darwin  ; export GOARCH=amd64  ; go build -o bin/transWARP-$GOARCH-$GOOS      transWARP.go
export GOOS=darwin  ; export GOARCH=arm64  ; go build -o bin/transWARP-$GOARCH-$GOOS      transWARP.go
export GOOS=linux   ; export GOARCH=amd64  ; go build -o bin/transWARP-$GOARCH-$GOOS      transWARP.go
export GOOS=linux   ; export GOARCH=386    ; go build -o bin/transWARP-$GOARCH-$GOOS      transWARP.go
export GOOS=linux   ; export GOARCH=arm    ; go build -o bin/transWARP-$GOARCH-$GOOS      transWARP.go
export GOOS=linux   ; export GOARCH=arm64  ; go build -o bin/transWARP-$GOARCH-$GOOS      transWARP.go
export GOOS=windows ; export GOARCH=amd64  ; go build -o bin/transWARP-$GOARCH-$GOOS.exe  transWARP.go

TAG=$(git tag --contains HEAD)
if [ -z "$TAG" ]
then
    # git_commit_id
    TAG=$(git rev-parse --short=15 HEAD)
fi

zip -9 -o -j -u transWARP-$TAG.zip $(git ls-files --others --exclude-standard bin) bin/readme.txt build/transWARP.bin ../warp-more-hardware-esp32-firmware/software/build/warpAC011K_firmware_2_0_12_64033399_merged.bin


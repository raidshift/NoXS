#!/bin/sh

build=2

git add . && git commit -S -m "build_$build" && git push

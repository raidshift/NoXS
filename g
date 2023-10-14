#!/bin/sh

build=2

git add . && git commit -m "build_$build" && git push

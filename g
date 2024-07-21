#!/bin/sh

build=2

GPG_TTY=$(tty)
export GPG_TTY
git add . && git commit -S -m "build_$build" && git push

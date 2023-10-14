#!/bin/sh

build=2

GPG_TTY=$(tty)
git add . && git commit -S -m "build_$build" && git push

#!/bin/sh

build=1

GPG_TTY=$(tty)
export GPG_TTY

git add . && git commit -S -m "1.2.$build" && git push

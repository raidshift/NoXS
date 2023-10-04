#!/bin/sh

build=$(grep -E 'let[ \t]+BUILD[ \t]+=[ \t]+[0-9]+' ./Sources/CLI/Build.swift | sed -E 's/let[ \t]+BUILD[ \t]+=[ \t]+([0-9]+)/\1/')
build=`expr $build + 1`
echo "let BUILD = "$build > ./Sources/CLI/Build.swift

git add . && git commit -m "build_$build" && git push

./build_install
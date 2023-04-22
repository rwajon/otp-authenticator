#!/bin/sh

while [ $# -gt 0 ]; do
  case "$1" in
  --target=*)
    target="${1#*=}"
    ;;
  *)
    printf "***************************\n"
    printf "* Error: Invalid argument (${1}).\n"
    printf "***************************\n"
    exit 1
    ;;
  esac
  shift
done

target=${target:-"aarch64-unknown-linux-gnu"}

hash cross 2>/dev/null || cargo install cross --git https://github.com/cross-rs/cross

cross build --target $target --release

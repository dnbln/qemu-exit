#!/usr/bin/env bash

if [[ $1 == *"aarch64"* ]]; then
    rust-objcopy --strip-all -O binary $1 $1.img
    STRIPPED_BINARY=$(echo $1.img | sed -e 's/.*target/target/g')

    qemu-system-aarch64 -M raspi3 -display none -semihosting -kernel $STRIPPED_BINARY
fi

let "status = $? - 13"
exit $status

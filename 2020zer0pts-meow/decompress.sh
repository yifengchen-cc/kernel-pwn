#!/bin/sh
mkdir -p initramfs
cd initramfs
cpio -vid < ../rootfs.cpio
cd ..
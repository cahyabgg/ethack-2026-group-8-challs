#!/bin/bash

cd source

docker compose up -d

CONTAINER_ID=$(docker compose ps -q tk_2)

LIBC_PATH="/usr/lib/x86_64-linux-gnu/libc.so.6"
LD_PATH="/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
CHALL_PATH="/home/challenge/chall"

docker cp "$CONTAINER_ID:$LIBC_PATH" ../solve/libc.so.6
docker cp "$CONTAINER_ID:$LD_PATH" ../solve/ld-linux-x86-64.so.2
docker cp "$CONTAINER_ID:$CHALL_PATH" ../solve/chall

chmod +x ../solve/chall ../solve/ld-linux-x86-64.so.2
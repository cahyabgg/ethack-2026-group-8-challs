#!/bin/bash
exec /usr/sbin/xinetd -dontfork

tail -f /dev/null
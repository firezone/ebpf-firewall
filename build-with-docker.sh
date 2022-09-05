#!/bin/bash
docker run --rm --user "$(id -u)":"$(id -g)" -v "$PWD":/usr/src/myapp -w /usr/src/myapp/userspace bpf-builder /bin/sh -c 'cargo build "$@"'
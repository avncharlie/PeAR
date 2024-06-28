#!/usr/bin/env bash

# To run without docker, make sure dependencies are install (see Dockerfile), then just: python -m pear ARGS

# Working directory is bind mounted under /workspace.
# Use this to send and recieve binaries for instrumentation.

# Change to location of IR cache (any folder, can start empty)
IR_CACHE="/ir/cache/folder"

docker run --platform linux/amd64 --rm --name=rewrite_container \
    -v $(pwd):/workspace \
    -v $(pwd)/pear:/pear \
    -v "$IR_CACHE":/ir_cache \
    -it pear_image "$@"

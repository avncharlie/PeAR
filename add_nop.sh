#!/usr/bin/env bash

# Working directory is bind mounted under /workspace.
# Use this to send and recieve binaries for instrumentation.

# Change to location of IR cache (any folder, can start empty)
IR_CACHE="/media/psf/Home/Documents/Uni/Honours/ir_cache"
IR_CACHE="/Users/alvin/Documents/Uni/Honours/ir_cache"

# This is probably/definitely not secure due to bind mounting the ssh keys
docker run --platform linux/amd64 --rm --name=rewrite_container \
    -v $(pwd):/workspace \
    -v $(pwd)/add_nop:/add_nop \
    -v "$IR_CACHE":/ir_cache \
    -v ~/.ssh:/root/.ssh \
    -it add_nop_image "$@"

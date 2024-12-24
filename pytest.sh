#!/usr/bin/env bash

# Add ddisasm and gtirb-pprinter commands via docker wrapper
source ./enable_wrappers.sh

pytest  "$@"

# remove commands
deactivate_wrappers

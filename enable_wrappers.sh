#!/bin/sh
#
# Add ddisasm and gtirb-pprinter wrapper commands (that actually call docker)

# to use, source this file, e.g:
# $ source ./enable_wrappers.sh
# then run deactive_wrappers to remove added commands

OLDPATH=$PATH
PATH="$(pwd)"/wrappers:$PATH
deactivate_wrappers() {
    PATH=$OLDPATH
}

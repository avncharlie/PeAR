#!/bin/sh
gcc -o simpleX64 ./simple.c
gcc -c -o hookX64.o shmem_hook/hook.c

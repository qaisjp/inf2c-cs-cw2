#!/bin/sh
set -o xtrace
gcc -Werror  -o mem_sim mem_sim.c -std=gnu99 -lm && valgrind ./mem_sim tlb+cache 16 4096 256 32 $1

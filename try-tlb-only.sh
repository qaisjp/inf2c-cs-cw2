#!/bin/sh
set -o xtrace
gcc -Werror  -o mem_sim mem_sim.c -std=gnu99 -lm && ./mem_sim tlb-only 16 4096 $1

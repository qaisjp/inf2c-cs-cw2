#!/bin/sh
gcc -o mem_sim mem_sim.c -std=gnu99 -lm && ./mem_sim cache-only 4096 256 32 mem_trace.txt

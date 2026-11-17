#!/usr/bin/env bash
set -a
source "agent/.env"
set +a

g++ -o agent/main agent/main.cpp && ./agent/main
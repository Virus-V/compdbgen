#!/usr/bin/env sh

# Detect OS and set appropriate compiler flags
if [ "$(uname)" = "Linux" ]; then
    echo "Building for Linux..."
    cc -g -I. -Icjson -D_GNU_SOURCE main.c mainloop.c cjson/cJSON.c cjson/cJSON_Utils.c -o compdbgen
elif [ "$(uname)" = "FreeBSD" ]; then
    echo "Building for FreeBSD..."
    cc -g -I. -Icjson main.c mainloop.c cjson/cJSON.c cjson/cJSON_Utils.c -o compdbgen
else
    echo "Unsupported operating system: $(uname)"
    exit 1
fi

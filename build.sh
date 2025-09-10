#!/usr/bin/env sh

cc -g -I. -Icjson main.c mainloop.c cjson/cJSON.c cjson/cJSON_Utils.c -o compdbgen

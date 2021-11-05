#!/bin/sh

clang-format \
    -style=file \
    -i \
    src/*.cpp \
    src/*.h

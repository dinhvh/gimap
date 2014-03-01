#!/bin/bash

clang++ -g -o gimap -I/usr/include/openssl -L/usr/bin/openssl -lssl gimap.cc

# Bonfire

[![Build Status](https://travis-ci.com/deerlets/bonfire.svg?branch=master)](https://travis-ci.com/deerlets/bonfire)

A service discovery and registry framework written in pure C.

## Supported platforms

- Linux
- MacOS
- Cygwin
- MinGW

## Dependences

- cmocka
- libzmq

## Build on Ubuntu
```
apt-get install libcmocka-dev libzmq3-dev
mkdir build && cd build
cmake .. && make
```

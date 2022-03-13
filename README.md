# Bonfire

[![Build status](https://ci.appveyor.com/api/projects/status/ch9uh7ryd9camp5d?svg=true)](https://ci.appveyor.com/project/yonzkon/bonfire)

A services framework written in C/C++, but can be used in pure C environment.

## Supported platforms

- Linux
- MacOS

## Dependences

- zeromq
- nlohmann-json

## Build on Ubuntu
```
apt-get install libzmq3-dev nlohmann-json3-dev
mkdir build && cd build
cmake .. && make
```

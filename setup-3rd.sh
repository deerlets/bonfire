#!/bin/bash
#
# Author: yonzkon <xiedd@zjrealtech.com>
# Maintainer: bart <shuxn@zjrealtech.com>
#

# Caution!! Don't touch this file unless you're clear of all the conceptions.

# usage
usage()
{
	echo -e "USAGE: $0 [ARCH] [REPOS]"
	echo -e "\tARCH   arm | x86, [default: x86]"
	echo -e "\tREPOS  git repository [default: gitlab]"
	echo -e ".e.g: $0"
	echo -e ".e.g: $0 debug x86 _output"
}
[[ "$*" =~ "help" ]] && usage && exit -1

# logging aspect
do_build()
{
	echo -e "\033[32m($(date '+%Y-%m-%d %H:%M:%S')): Building $1\033[0m"
	$*
	echo -e "\033[32m($(date '+%Y-%m-%d %H:%M:%S')): Finished $1\033[0m"
}

# change directory to the location of this script
ORIGIN_PWD=$(pwd)
SCRIPT_DIR=$(cd `dirname $0`; pwd)

# parse options
ARCH=x86 && [ -n "$1" ] && ARCH=$1
REPOS=gitlab && [ -n "$2" ] && REPOS=$2
PREFIX=$SCRIPT_DIR
[ -z "$JOBS" ] && ((JOBS=$(grep -c ^processor /proc/cpuinfo)-1))

# git base
GIT_BASE=ssh://git@gitlab02.zjrealtech.com:3289

# setup cross-chain
export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig
if [ "$ARCH" = "arm" ]; then
	export CC=/opt/arm/bin/arm-linux-gnueabi-gcc
	export CXX=/opt/arm/bin/arm-linux-gnueabi-g++
	export STRIP=/opt/arm/bin/arm-linux-gnueabi-strip
	export AR=/opt/arm/bin/arm-linux-gnueabi-ar
else
	export CC=gcc
	export CXX=g++
	export STRIP=strip
	export AR=ar
fi

libpgm()
{
	libpgm_path=$PREFIX/thirdparty/libpgm
	if [ ! -e $libpgm_path ]; then
		if [ "$REPOS" = github ]; then
			git clone https://github.com/steve-o/openpgm.git $libpgm_path
		else
			git clone $GIT_BASE/mirrors/openpgm.git $libpgm_path
		fi
		git -C $libpgm_path checkout release-5-2-122
	fi

	if [ ! "$(find $PREFIX/lib -maxdepth 1 -name ${FUNCNAME[0]}*)" ]; then
		cd $libpgm_path/openpgm/pgm
		aclocal
		libtoolize --force
		automake --add-missing
		autoreconf --force --install
		./configure --prefix=$PREFIX
		make && make install
	fi
}

libzmq()
{
	libzeromq_path=$PREFIX/thirdparty/libzeromq
	if [ ! -e $libzeromq_path ]; then
		if [ "$REPOS" = github ]; then
			git clone https://github.com/zeromq/libzmq.git $libzeromq_path
		else
			git clone $GIT_BASE/mirrors/libzmq.git $libzeromq_path
		fi
		git -C $libzeromq_path checkout v4.2.5
	fi

	if [ ! "$(find $PREFIX/lib -maxdepth 1 -name ${FUNCNAME[0]}*)" ]; then
		mkdir -p $libzeromq_path/build && cd $libzeromq_path/build
		cmake .. -DWITH_OPENPGM=1 -DBUILD_TESTS=off -DWITH_PERF_TOOL=off \
			-DCMAKE_INSTALL_PREFIX=$PREFIX
		make && make install
	fi
}

libgtest()
{
	libgtest_path=$PREFIX/thirdparty/libgtest
	if [ ! -e $libgtest_path ]; then
		if [ "$REPOS" = github ]; then
			git clone https://github.com/google/googletest.git $libgtest_path
		else
			git clone $GIT_BASE/mirrors/googletest.git $libgtest_path
		fi
		git -C $libgtest_path checkout release-1.8.0
	fi

	if [ ! "$(find $PREFIX/lib -maxdepth 1 -name ${FUNCNAME[0]}*)" ]; then
		cd $libgtest_path
		cmake -DCMAKE_INSTALL_PREFIX:PATH=$PREFIX
		make && make install
	fi
}

do_build libpgm
do_build libzmq
do_build libgtest

[ -e $PREFIX/lib64 ] && cp -a $PREFIX/lib64/* $PREFIX/lib/
rm -rf $PREFIX/lib64
rm -rf $PREFIX/share
rm -rf $PREFIX/doc/zmq

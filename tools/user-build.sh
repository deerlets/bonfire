#!/bin/bash

libgtest()
{
    googletest_path=$PROJECT_DIR/deps/googletest

    if [ ! "$(find $PROJECT_DIR/lib* -maxdepth 1 -name *${FUNCNAME[0]}*)" ]; then
        mkdir -p $googletest_path/build && cd $googletest_path/build
        cmake .. -DCMAKE_INSTALL_PREFIX:PATH=$PROJECT_DIR
        make -j$JOBS && make install
        [ ! $? -eq 0 ] && exit 1
    fi
}

libzmq()
{
    libzmq_path=$PROJECT_DIR/deps/libzmq

    if [ ! "$(find $PROJECT_DIR/lib* -maxdepth 1 -name *${FUNCNAME[0]}*)" ]; then
        mkdir -p $libzmq_path/build && cd $libzmq_path/build
        cmake .. -DCMAKE_INSTALL_PREFIX:PATH=$PROJECT_DIR \
            -DBUILD_TESTS=off -DWITH_PERF_TOOL=off
        make -j$JOBS && make install
        [ ! $? -eq 0 ] && exit 1
    fi
}

extlibc()
{
    extlibc_path=$PROJECT_DIR/deps/extlibc

    if [ ! "$(find $PROJECT_DIR/lib* -maxdepth 1 -name *libcx*)" ]; then
        mkdir -p $extlibc_path/build && cd $extlibc_path/build
        cmake .. -DCMAKE_INSTALL_PREFIX:PATH=$PROJECT_DIR \
            -DBUILD_TESTS=off -DBUILD_SHARED=off
        make -j$JOBS && make install
        [ ! $? -eq 0 ] && exit 1
    fi
}

zebra()
{
    mkdir -p $PROJECT_DIR/build && cd $PROJECT_DIR/build
    cmake .. -DBUILD_TESTS=on -DBUILD_DEBUG=$DEBUG && make -j$JOBS && make test
    [ ! $? -eq 0 ] && exit 1
}

main()
{
    do_build libgtest
    do_build libzmq
    do_build extlibc
    do_build zebra
}

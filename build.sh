#!/usr/bin/env sh

which ndk-build 2>&1 >/dev/null || exit 1
if [ -z $ANDROID_SDK -o ! -d $ANDROID_SDK ]; then
    exit 1
fi

NDK_CLEAN=
ANT_CLEAN=
if [ "x$1" = "xclean" ]; then
    NDK_CLEAN=-B
    ANT_CLEAN=clean
fi

# build native stuffs
ndk-build $NDK_CLEAN

# add appcompat_v7 to build path
# library only works with relative path
APPCOMPAT=../appcompat_v7
if [ ! -d $APPCOMPAT ]; then
    ln -sf $ANDROID_SDK/extras/android/support/v7/appcompat $APPCOMPAT
fi
# generate build.xml for appcompat_v7
if [ ! -f $APPCOMPAT/build.xml ]; then
    cd $APPCOMPAT
    android update project --path $PWD
    cd -
fi
android update project --path $PWD --target android-19
# now it's OK to build
ant $ANT_CLEAN debug


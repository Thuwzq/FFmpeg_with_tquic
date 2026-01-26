#!/bin/sh

# clean previous builds
./clean_ios.sh

# directories
FF_VERSION="7.1.1"
if [[ $FFMPEG_VERSION != "" ]]; then
  FF_VERSION=$FFMPEG_VERSION
fi

SOURCE="../../"
FAT="ios_fat"
SCRATCH="scratch"
# must be an absolute path
THIN=`pwd`/"thin"

# absolute path to other libraries
#X264=`pwd`/fat-x264
#FDK_AAC=`pwd`/../fdk-aac-build-script-for-iOS/fdk-aac-ios
LIBEV=`pwd`/"../../third_party/libev"

# disable intel accelerate module qsv
CONFIGURE_FLAGS="--enable-cross-compile --disable-debug --disable-programs \
                 --disable-doc \
                 --disable-x86asm --disable-libmfx --disable-hwaccels \
                 --enable-videotoolbox --enable-audiotoolbox --disable-bzlib --disable-zlib \
                 --disable-avdevice --disable-avfilter --disable-swresample \
                 --disable-decoder=vvc --disable-demuxer=vvc --disable-muxer=vvc"
# if [ "$X264" ]
# then
#     CONFIGURE_FLAGS="$CONFIGURE_FLAGS --enable-gpl --enable-libx264"
# fi

# if [ "$FDK_AAC" ]
# then
#     CONFIGURE_FLAGS="$CONFIGURE_FLAGS --enable-libfdk-aac --enable-nonfree"
# fi

# avresample
#CONFIGURE_FLAGS="$CONFIGURE_FLAGS --enable-avresample"

# support archs
ARCHS="arm64"

COMTQUIC="y"
COMLIBEV="y"
COMPILE="y"
LIPO="y"


DEPLOYMENT_TARGET="12.0"

if [ "$*" ]
then
    if [ "$*" = "lipo" ]
    then
        # skip compile
        COMPILE=
    elif [ "$*" = "--help" ] || [ "$*" = "-h" ]
    then
        echo "Usage: $0 [lipo]"
        echo "  lipo: only copy arm64 libraries, skip compilation"
        exit 0
    else
        echo "Error: This script now only supports arm64 architecture"
        echo "Usage: $0 [lipo]"
        exit 1
    fi
fi


# Build TQUIC libs for IOS
if [ "$COMTQUIC" ]
then
    echo "Building TQUIC libs for iOS"

    # Clean TQUIC
    cd ../../third_party/tquic
    cargo clean

    # Compile TQUIC for IOS arm64 only
    xcode-select --install
    rustup target add aarch64-apple-ios
    cargo build --target aarch64-apple-ios --features ffi --release

    cd ../../build/ios
fi

# Build libev for iOS
if [ "$COMLIBEV" ]
then
    echo "Building libev for iOS"
    
    # Build libev using the dedicated iOS build script
    cd "$LIBEV"
    
    # Clean previous build artifacts to ensure fresh compilation
    if [ -d "ios_build" ]; then
        echo "Cleaning previous libev build artifacts..."
        rm -rf ios_build
    fi
    
    chmod +x build_ios.sh
    ./build_ios.sh
    
    cd ../../build/ios
fi

if [ "$COMPILE" ]
then
    if [ ! `which yasm` ]
    then
        echo 'Yasm not found'
        if [ ! `which brew` ]
        then
            echo 'Homebrew not found. Trying to install...'
            ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)" \
            || exit 1
        fi
        echo 'Trying to install Yasm...'
        brew install yasm || exit 1
    fi
    if [ ! `which gas-preprocessor.pl` ]
    then
        echo 'gas-preprocessor.pl not found. Trying to install...'
        (curl -L https://github.com/libav/gas-preprocessor/raw/master/gas-preprocessor.pl \
        -o /usr/local/bin/gas-preprocessor.pl \
        && chmod +x /usr/local/bin/gas-preprocessor.pl) \
        || exit 1
    fi

    # if [ ! -r $SOURCE ]
    # then
    #     echo 'FFmpeg source not found. Trying to download...'
    #     curl http://www.ffmpeg.org/releases/$SOURCE.tar.bz2 | tar xj \
    #     || exit 1
    # fi

    CWD=`pwd`
    ../../make clean
    echo "building ffmpeg arm64 ..."
    mkdir -p "$SCRATCH/arm64"
    cd "$SCRATCH/arm64"

    CFLAGS="-arch arm64"
    PLATFORM="iPhoneOS"
    CFLAGS="$CFLAGS -mios-version-min=$DEPLOYMENT_TARGET -fembed-bitcode"
    EXPORT="GASPP_FIX_XCODE5=1"

    XCRUN_SDK=`echo $PLATFORM | tr '[:upper:]' '[:lower:]'`
    CC="xcrun -sdk $XCRUN_SDK clang"

    # force "configure" to use "gas-preprocessor.pl" (FFmpeg 3.3)
    AS="gas-preprocessor.pl -arch aarch64 -- $CC"

    CXXFLAGS="$CFLAGS"
    LDFLAGS="$CFLAGS"

    # Set library paths for arm64
    TQUIC_TARGET="aarch64-apple-ios"
    
    # Add tquic include and library paths
    CFLAGS="$CFLAGS -I../../../../third_party/tquic/include"
    LDFLAGS="$LDFLAGS -L../../../../third_party/tquic/target/aarch64-apple-ios/release -ltquic"
    
    # Add ssl and crypto head files and library paths
    CFLAGS="$CFLAGS -I../../../../third_party/tquic/deps/boringssl/src/include"
    # SSL_BUILD_DIR="../../../../third_party/tquic/target/$TQUIC_TARGET/release/build/tquic-*/out/build"
    # LDFLAGS="$LDFLAGS -L$SSL_BUILD_DIR -lssl -lcrypto"
    
    # Add libev include and library paths
    CFLAGS="$CFLAGS -I$LIBEV/ios_build/arm64/include"
    LDFLAGS="$LDFLAGS -L$LIBEV/ios_build/arm64/lib -lev"
    
    # if [ "$X264" ]
    # then
    #     CFLAGS="$CFLAGS -I$X264/include"
    #     LDFLAGS="$LDFLAGS -L$X264/lib"
    # fi
    # if [ "$FDK_AAC" ]
    # then
    #     CFLAGS="$CFLAGS -I$FDK_AAC/include"
    #     LDFLAGS="$LDFLAGS -L$FDK_AAC/lib"
    # fi

    TMPDIR=${TMPDIR/%\/} $CWD/$SOURCE/configure \
            --target-os=darwin \
            --arch=arm64 \
            --cc="$CC" \
            --as="$AS" \
            $CONFIGURE_FLAGS \
            --extra-cflags="$CFLAGS" \
            --extra-ldflags="$LDFLAGS" \
            --prefix="$THIN/arm64" \
            || exit 1
            
            echo "TMPDIR="$TMPDIR
            make -j3 install $EXPORT || exit 1
            cd $CWD

    cp ../../third_party/tquic/target/aarch64-apple-ios/release/libtquic.a $THIN/arm64/lib
    cp ../../third_party/libev/ios_build/arm64/lib/libev.a $THIN/arm64/lib
fi

if [ "$LIPO" ]
then
    echo "copying arm64 binaries..."
    mkdir -p $FAT/lib
    CWD=`pwd`
    
    # Copy libraries from arm64 directory
    cp -rf $THIN/arm64/lib/*.a $FAT/lib/ || exit 1
    
    # Copy include files
    cp -rf $THIN/arm64/include $FAT/
fi

echo Done

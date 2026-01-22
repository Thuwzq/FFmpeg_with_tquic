#!/bin/sh

# libev iOS build script
# This script builds libev as a static library for iOS architectures

LIBEV_DIR=$(cd "$(dirname "$0")"; pwd)
BUILD_DIR="$LIBEV_DIR/ios_build"
DEPLOYMENT_TARGET="12.0"

# Supported architectures
ARCHS="arm64"

# Clean previous builds
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Function to build for a specific architecture
build_arch() {
    local ARCH=$1
    local BUILD_ARCH_DIR="$BUILD_DIR/$ARCH"
    
    echo "Building libev for $ARCH..."
    
    # Create build directory
    mkdir -p "$BUILD_ARCH_DIR/lib"
    mkdir -p "$BUILD_ARCH_DIR/include"
    
    # Set up compiler flags for iOS
    if [ "$ARCH" = "x86_64" ]
    then
        PLATFORM="iPhoneSimulator"
        SDKROOT=$(xcrun --sdk iphonesimulator --show-sdk-path)
        CFLAGS="-arch $ARCH -mios-simulator-version-min=$DEPLOYMENT_TARGET -isysroot $SDKROOT -I$LIBEV_DIR"
    else
        PLATFORM="iPhoneOS"
        SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path)
        CFLAGS="-arch $ARCH -mios-version-min=$DEPLOYMENT_TARGET -fembed-bitcode -isysroot $SDKROOT -I$LIBEV_DIR"
    fi
    
    # Compile libev source files
    cd "$LIBEV_DIR"
    
    # Compile ev.c
    echo "Compiling ev.c for $ARCH..."
    xcrun -sdk $(echo $PLATFORM | tr '[:upper:]' '[:lower:]') clang $CFLAGS -c ev.c -o "$BUILD_ARCH_DIR/ev.o"
    
    # Compile event.c
    echo "Compiling event.c for $ARCH..."
    xcrun -sdk $(echo $PLATFORM | tr '[:upper:]' '[:lower:]') clang $CFLAGS -c event.c -o "$BUILD_ARCH_DIR/event.o"
    
    # Create static library
    echo "Creating static library for $ARCH..."
    libtool -static "$BUILD_ARCH_DIR/ev.o" "$BUILD_ARCH_DIR/event.o" -o "$BUILD_ARCH_DIR/lib/libev.a"
    
    # Copy headers
    cp ev.h "$BUILD_ARCH_DIR/include/"
    cp event.h "$BUILD_ARCH_DIR/include/"
    cp ev++.h "$BUILD_ARCH_DIR/include/"
    
    # Clean up object files
    rm -f "$BUILD_ARCH_DIR/ev.o" "$BUILD_ARCH_DIR/event.o"
    
    echo "libev built for $ARCH at $BUILD_ARCH_DIR"
}

# Build for each architecture
for ARCH in $ARCHS
do
    build_arch $ARCH
done

# Create universal library
echo "Creating universal libev library..."
UNIVERSAL_DIR="$BUILD_DIR/universal"
mkdir -p "$UNIVERSAL_DIR/lib"
mkdir -p "$UNIVERSAL_DIR/include"

# Copy headers from first architecture
cp "$BUILD_DIR/arm64/include/"*.h "$UNIVERSAL_DIR/include/"

# Create universal library
lipo -create \
    "$BUILD_DIR/arm64/lib/libev.a" \
    "$BUILD_DIR/x86_64/lib/libev.a" \
    -output "$UNIVERSAL_DIR/lib/libev.a"

echo "Universal libev library created at $UNIVERSAL_DIR"
echo "Headers: $UNIVERSAL_DIR/include/"
echo "Library: $UNIVERSAL_DIR/lib/libev.a"

echo "libev iOS build completed successfully!"
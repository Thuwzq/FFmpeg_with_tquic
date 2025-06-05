# FFmpeg-with-TQUIC README

## Introduction
Add TQUIC lib to FFmpeg network component

## Requirements
- FFmpeg version: 7.1.1 https://github.com/FFmpeg/FFmpeg/tree/n7.1.1
- QUIC version: TQUIC 1.6.0 https://github.com/Tencent/tquic/tree/release/v1.6.0

## Enviroments
We have run this project on MacOS ARM system, but we do not guarantee working on other systems.

## Build
```bash
# Get source code
git clone https://github.com/Thuwzq/FFmpeg_with_tquic.git --recursive

# Build TQUIC
cd third_party/tquic
cargo build --release -F ffi


#build ffmpeg
#openssl and pthreads must be included, you can set other modules as you want
#configure example below:
./configure --prefix=/usr/local/ffmpeg --extra-cflags=-I/path/to/ev.h --extra-ldflags="/path/to/libev.a ./third_party/tquic/target/release/libtquic.a" --enable-gpl --enable-openssl --enable-nonfree --enable-libfdk-aac --enable-libx264 --enable-libx265 --enable-filter=delogo --enable-debug --disable-optimizations --enable-libspeex --enable-videotoolbox --enable-shared --enable-pthreads --enable-version3 --enable-hardcoded-tables --cc=clang --host-cflags= --host-ldflags=

make
sudo make install

```

## Run TQUIC Server
reference: https://tquic.net/zh/docs/getting_started/demo

## Run ffplay with TQUIC
```
ffplay "tquic://ip:port/filename"
```
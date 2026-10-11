This is a file compression / decompression tool built with Rust.

## Features
 - Fast XZ file decompression

Currently, only decompression is implemented, with only LZMA2 and Delta filters supported.
Work will be done in the future for compression and filter support

## Getting started

Below are instructions for compiling the project for your setup. If you do not wish do compile from source, use the precompiled release from Github

  

### Prerequisites

- Rust Cargo 1.97.1+

  

### Installation

``` bash
git clone https://github.com/BalashankarMc/rip-xz/
cd rip-xz
make install
sudo cp rz /usr/bin
```

  The last `cp` is only needed if you want to use

```bash
rz decompress input.xz output
```

from any directory

### Usage

```bash
rz decompress input.xz output
```

## Performance

Benchmarked on an Intel Core i7-1195G7 with 12GB DDR4 RAM on Arch Linux

| Operation         | RipXZ  | XZ     |
| ----------------- | ------ | ------ |
| Decompress - 35MB | ~450ms | ~430ms |

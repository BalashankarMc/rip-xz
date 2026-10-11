This is a file compression / decompression tool built with Rust.

## Features
 - Undergoing re-write


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
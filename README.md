# asu

asu (Assembly Utility) is the missing command-line tool that converts assembly code to raw bytes and vice versa.

The assembly functionalities are provided by the [Keystone Engine](https://www.keystone-engine.org/) and the disassembly functionalities are provided by the [Capstone Engine](https://www.capstone-engine.org/).

![Image](https://github.com/user-attachments/assets/f4935d35-e625-4f27-b927-667657f565f5)

## Installation

You can download pre-built binaries on the [releases page](https://github.com/k4yt3x/asu/releases/latest).

For Arch Linux users, you can install `asu` from the AUR:

```bash
yay -S asu
```

## Building From Source

Pre-requisites:

- C++17 compiler
- CMake 3.10 or later
- Capstone Engine
- Keystone Engine
- argparse

```bash
cmake -S . -B build  -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
```

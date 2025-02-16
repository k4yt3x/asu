# asu

> [!NOTE]
> As I finished making this tool I realized [rasm2](https://book.rada.re/tools/rasm2/intro.html) from Radare2 can do the job. I will leave this repository here, but you might want to use the more mature and feature-rich `rasm2` instead.

asu (Assembly Utility) is the a command-line tool that converts assembly code to raw bytes and vice versa.

The assembly functionalities are provided by the [Keystone Engine](https://www.keystone-engine.org/) and the disassembly functionalities are provided by the [Capstone Engine](https://www.capstone-engine.org/).

![Image](https://github.com/user-attachments/assets/f4935d35-e625-4f27-b927-667657f565f5)

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

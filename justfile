bindir := "build"
generator := "Ninja"
cxx := "clang++"

[unix]
build:
    cmake -G '{{generator}}' -S . -B {{bindir}} \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_CXX_COMPILER={{cxx}} \
        -DCMAKE_BUILD_TYPE=Release
    cmake --build {{bindir}} --config Release --parallel

[unix]
clean:
    rm -rf {{bindir}} .cache

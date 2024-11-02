# ElfLoader

![](https://img.shields.io/badge/Android-7%20~%2015-brightgreen)
![](https://img.shields.io/badge/Arch-arm64%20%2F%20arm%20%2F%20x86%20%2F%20x64%20%2F%20riscv64-red.svg)

Loading ELF in android using pure java

使用纯 java 在 android 上加载 ELF

## Features

- [x] Loading shared libraries and call `JNI_OnLoad` if exists
- [ ] Loading in-memory shared libraries
    - [x] arm64
    - [ ] arm
    - [ ] x86
    - [ ] x64
    - [ ] riscv64
- [x] Lookup symbols in `.dynsym`
- [x] Lookup debugging symbols in `.symtab`
- [ ] Lookup debugging symbols in `.gnu_debugdata` (not planned, do we really need it?)

## 特征

- [x] 加载动态库，如果存在则调用 `JNI_OnLoad`
- [ ] 加载内存中的动态库
    - [x] arm64
    - [ ] arm
    - [ ] x86
    - [ ] x64
    - [ ] riscv64
- [x] 查找 `.dynsym` 中的符号
- [x] 查找 `.symtab` 中的调试符号
- [ ] 查找 `.gnu_debugdata` 中的调试符号 (未计划, 真的需要?)


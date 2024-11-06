# RedTeamOps

## Description

使用 Rust 实现一些免杀技术，主要用于个人学习。

## Contents

- [APC 注入](./apc-injection/)
- [Callback 函数执行](./callback-injection/)
- [CreateThread/RemoteThread 注入](./create-thread-injection/)
- [Hells Halos Tartarus Gate](./syscall/src/gate.rs)
- [Layered Syscall](./layered-syscall/)
- ...


## Usage & Testing

windows 下 cargo build 即可。主目录下的 `test.bin` 是一个测试 shellcode，会在执行时向 console 输出 Test，并调用 calc.exe。


## Acknowledgements

- [joaoviictorti/RustRedOps](https://github.com/joaoviictorti/RustRedOps): a repository for advanced Red Team techniques and offensive malware, focused on Rust
- [safedv/Rustic64](https://github.com/safedv/Rustic64): 64-bit, position-independent implant template for Windows in Rust
- [MSxDOS/ntapi](https://github.com/MSxDOS/ntapi): Rust FFI bindings for Native API
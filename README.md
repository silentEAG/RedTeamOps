# RedTeamOps

Use Rust to implement some Red Team techniques :)
Note that this project is for self-learning and research purposes only!

## Contents

- [APC Injection (Early Bird in user mode)](./apc-injection/)
- [Callback Function](./callback-injection/)
- [CreateThread/RemoteThread Injection](./create-thread-injection/)
- [Hells Halos Tartarus Gate](./syscall/src/gate.rs)
- [Layered Syscall](./layered-syscall/)
- [Early Cascade Injection](./early-cascade-injection/)
- ...


## Usage & Testing

Just run `cargo build` & `cargo run` in windows environment.

Here is a test binary shellcode which will print "Test" to the console and execute `calc.exe`.


## Credits

- [joaoviictorti/RustRedOps](https://github.com/joaoviictorti/RustRedOps): a repository for advanced Red Team techniques and offensive malware, focused on Rust
- [safedv/Rustic64](https://github.com/safedv/Rustic64): 64-bit, position-independent implant template for Windows in Rust
- [MSxDOS/ntapi](https://github.com/MSxDOS/ntapi): Rust FFI bindings for Native API
- Earlycascade Injection
  - [introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/)
  - [Cracked5pider/earlycascade-injection](https://github.com/Cracked5pider/earlycascade-injection)
  - [Teach2Breach/early_cascade_inj_rs](https://github.com/Teach2Breach/early_cascade_inj_rs)
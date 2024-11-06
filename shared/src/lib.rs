pub mod ntpeb;
pub mod utils;

pub trait Executor {
    fn execute(&self, shellcode: Vec<u8>) -> anyhow::Result<()>;
}

pub fn simple_load_from_file() -> Vec<u8> {
    let args: Vec<String> = std::env::args().collect();
    let filename = &args[1];
    std::fs::read(filename).unwrap()
}

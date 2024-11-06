use std::io::{stdin, stdout, Write};

#[macro_export]
macro_rules! check {
    ($e:expr) => {
        if ($e) == false {
            panic!(
                "{} failed: {}!",
                stringify!($e),
                windows_sys::Win32::Foundation::GetLastError()
            );
        }
    };
}

pub fn breakpoint() {
    let mut stdout = stdout();
    stdout
        .write_all(b"[*] Press Enter to continue...\n")
        .unwrap();
    stdout.flush().unwrap();
    let mut str = String::new();
    stdin().read_line(&mut str).unwrap();
}

/// Computes the DJB2 hash for the given buffer
pub fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hash: u32 = 1845;

    for c in buffer {
        let mut cur = *c;
        if cur == 0 {
            continue;
        }
        if cur >= b'a' {
            cur -= 0x20;
        }
        hash = ((hash << 5).wrapping_add(hash)) + (cur as u32);
    }
    hash
}

/// Calculates the length of a C-style null-terminated string.
///
/// This function counts the number of characters in the string until it encounters a null byte.
pub fn get_cstr_len(pointer: *const char) -> usize {
    let mut tmp: u64 = pointer as u64;

    // Iterate over the string until a null byte (0) is found
    unsafe {
        while *(tmp as *const u8) != 0 {
            tmp += 1;
        }
    }

    // Return the length of the string (difference between the end and start)
    (tmp - pointer as u64) as _
}

#[test]
fn test_dbj2_hash() {
    let hash = dbj2_hash(b"ntdll.dll");
    println!("ntdll.dll hash: {:#x}", hash);
}

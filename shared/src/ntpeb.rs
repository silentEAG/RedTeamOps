use core::arch::asm;
use core::ptr::null_mut;

use ntapi::ntpebteb::PEB;
use ntapi::{
    ntheader::{
        ImageDosHeader, ImageExportDirectory, ImageNtHeaders, IMAGE_DOS_SIGNATURE,
        IMAGE_NT_SIGNATURE,
    },
    ntldr::LDR_DATA_TABLE_ENTRY,
};

use crate::utils::{dbj2_hash, get_cstr_len};

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use super::*;

    pub fn find_peb() -> *mut PEB {
        let peb: *mut PEB;
        unsafe {
            asm!(
                "mov {}, gs:[0x60]",
                out(reg) peb
            );
        }
        peb
    }
}

#[cfg(target_arch = "x86")]
mod x86 {
    use super::*;

    pub fn find_peb() -> *mut PEB {
        let peb: *mut PEB;
        unsafe {
            asm!(
                "mov {}, fs:[0x30]",
                out(reg) peb
            );
        }
        peb
    }
}

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "x86")]
pub use x86::*;

pub const NTDLL_HASH: u32 = 0x4ce6191d;
pub const KERNEL32_HASH: u32 = 0x1d284f85;

/// # Safety
pub unsafe fn ldr_module_base_addr(module_hash: u32) -> *mut u8 {
    let dll = ldr_module(module_hash);
    if dll.is_null() {
        return null_mut();
    }
    (*dll).DllBase as *mut u8
}

/// # Safety
pub unsafe fn ldr_module(module_hash: u32) -> *mut LDR_DATA_TABLE_ENTRY {
    let peb = find_peb();

    if peb.is_null() {
        return null_mut();
    }

    let ldr = (*peb).Ldr;
    let mut module_list = (*ldr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while !(*module_list).DllBase.is_null() {
        let dll_name_buffer_ptr = (*module_list).BaseDllName.Buffer;
        let dll_name_length = (*module_list).BaseDllName.Length;

        let dll_name =
            std::slice::from_raw_parts(dll_name_buffer_ptr as *const u8, dll_name_length as usize);
        if module_hash == dbj2_hash(dll_name) {
            return module_list;
        }

        module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }
    null_mut()
}

/// # Safety
pub unsafe fn get_nt_headers(base_addr: *mut u8) -> *mut ImageNtHeaders {
    let dos_header = base_addr as *mut ImageDosHeader;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return null_mut();
    }
    let nt_headers = (base_addr as isize + (*dos_header).e_lfanew as isize) as *mut ImageNtHeaders;
    if (*nt_headers).signature != IMAGE_NT_SIGNATURE as _ {
        return null_mut();
    }
    nt_headers
}
/// # Safety
pub unsafe fn ldr_function(module_base: *mut u8, function_hash: u32) -> *mut u8 {
    let p_img_nt_headers = get_nt_headers(module_base);

    if p_img_nt_headers.is_null() {
        return null_mut();
    }

    let data_directory = &(*p_img_nt_headers).optional_header.data_directory[0];
    let export_directory =
        (module_base.offset(data_directory.virtual_address as isize)) as *mut ImageExportDirectory;
    if export_directory.is_null() {
        return null_mut();
    }

    let number_of_functions = (*export_directory).number_of_functions;
    let array_of_names =
        module_base.offset((*export_directory).address_of_names as isize) as *const u32;
    let array_of_addresses =
        module_base.offset((*export_directory).address_of_functions as isize) as *const u32;
    let array_of_ordinals =
        module_base.offset((*export_directory).address_of_name_ordinals as isize) as *const u16;

    let names = core::slice::from_raw_parts(array_of_names, number_of_functions as _);
    let functions = core::slice::from_raw_parts(array_of_addresses, number_of_functions as _);
    let ordinals = core::slice::from_raw_parts(array_of_ordinals, number_of_functions as _);

    for i in 0..number_of_functions {
        let name_addr = module_base.offset(names[i as usize] as isize) as *const i8;
        let name_len = get_cstr_len(name_addr as _);
        let name_slice: &[u8] = core::slice::from_raw_parts(name_addr as _, name_len);

        if function_hash == dbj2_hash(name_slice) {
            let ordinal = ordinals[i as usize] as usize;
            return module_base.offset(functions[ordinal] as isize);
        }
    }

    null_mut()
}

#[cfg(test)]
mod tests {

    use ntapi::ntrtl::RtlInitUnicodeString;

    use super::*;

    #[test]
    fn test_ldr_module() {
        let kernel32_hash = dbj2_hash(b"kernel32.dll");
        let kernel32_base = unsafe { ldr_module(kernel32_hash) };
        assert!(!kernel32_base.is_null());

        // println!("kernel32.dll base address: {:p}", kernel32_base);
    }

    #[test]
    fn test_get_nt_headers() {
        let kernel32_hash = dbj2_hash(b"kernel32.dll");
        let kernel32_base = unsafe { ldr_module_base_addr(kernel32_hash) };
        assert!(!kernel32_base.is_null());

        let nt_headers = unsafe { get_nt_headers(kernel32_base) };
        assert!(!nt_headers.is_null());

        // println!("kernel32.dll nt headers: {:p}", nt_headers);
    }

    #[test]
    fn test_ldr_function() {
        let kernel32_hash = dbj2_hash(b"kernel32.dll");
        let kernel32_base = unsafe { ldr_module_base_addr(kernel32_hash) };
        assert!(!kernel32_base.is_null());

        let nt_headers = unsafe { get_nt_headers(kernel32_base) };
        assert!(!nt_headers.is_null());

        let winexec_hash = dbj2_hash(b"WinExec");
        let winexec = unsafe { ldr_function(kernel32_base, winexec_hash as _) };
        assert!(!winexec.is_null());

        // println!("WinExec address: {:p}", winexec);
        // type WinExec = unsafe extern "system" fn(
        //     lpCmdLine: *mut std::ffi::c_void,
        //     uCmdShow: *const u32,
        // ) -> i32;
        // let winexec: WinExec = unsafe { core::mem::transmute(winexec) };
        // unsafe {
        //     winexec("calc\0".as_ptr() as *mut std::ffi::c_void, null_mut());
        // }
    }

    #[test]
    fn other_test() {

        fn to_pwstr(text: &'static str) -> *mut u16 {
            text.encode_utf16().chain(::std::iter::once(0)).collect::<Vec<u16>>().as_mut_ptr()
        }

        unsafe {
            let destination_str = null_mut();

            println!("0");
    
            RtlInitUnicodeString(
                destination_str,
                to_pwstr("\\??\\C:\\Windows\\System32\\calc.exe")
            );
    
            println!("1");
        }

    }
}

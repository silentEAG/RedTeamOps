use core::ptr::{null, null_mut};
use core::ffi::c_void;
use core::mem::MaybeUninit;

use layered_syscall::hook::{destroy_hooks, initialize_hooks, set_hw_bp};
use ntapi::ntpsapi::{PsCreateInitialState, ACCESS_MASK, PPS_ATTRIBUTE_LIST, PPS_CREATE_INFO, PS_CREATE_INFO};
use ntapi::ntrtl::{RtlCreateProcessParametersEx, RtlDestroyProcessParameters, RtlFreeHeap, PRTL_USER_PROCESS_PARAMETERS};
use ntapi::{
    ntpsapi::{NtCreateUserProcess, PS_ATTRIBUTE, PS_ATTRIBUTE_IMAGE_NAME, PS_ATTRIBUTE_LIST},
    ntrtl::{RtlAllocateHeap, RtlCreateProcessParameters, RtlInitUnicodeString, RtlProcessHeap},
};
use shared::{
    ntpeb::{ldr_function, ldr_module_base_addr, NTDLL_HASH},
    utils::dbj2_hash,
};
use ntapi::winapi::shared::ntdef::*;
use syscall::gate::get_ssn;
use widestring::U16CString;
use windows_sys::Win32::System::Threading::{PROCESS_ALL_ACCESS, STARTF_USESHOWWINDOW, THREAD_ALL_ACCESS};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows_sys::{core::PWSTR, Win32::System::Memory::HEAP_ZERO_MEMORY};

fn wrp_nt_create_user_process(
    ProcessHandle: PHANDLE,
    ThreadHandle: PHANDLE,
    ProcessDesiredAccess: ACCESS_MASK,
    ThreadDesiredAccess: ACCESS_MASK,
    ProcessObjectAttributes: POBJECT_ATTRIBUTES,
    ThreadObjectAttributes: POBJECT_ATTRIBUTES,
    ProcessFlags: ULONG,
    ThreadFlags: ULONG,
    ProcessParameters: PVOID,
    CreateInfo: PPS_CREATE_INFO,
    AttributeList: PPS_ATTRIBUTE_LIST,
) -> NTSTATUS {
    unsafe {
        let hash = dbj2_hash(b"NtCreateUserProcess");

        println!("NtCreateUserProcess hash: {:#X}", hash);

        let function_addr = NtCreateUserProcess as u64;
        let ssn = get_ssn(hash).unwrap();

        println!("NtCreateUserProcess: {:#X}", function_addr as usize);
        println!("SSN for NtCreateUserProcess: {:#X}", ssn);

        set_hw_bp(function_addr, true, ssn);

        NtCreateUserProcess(
            ProcessHandle,
            ThreadHandle,
            ProcessDesiredAccess,
            ThreadDesiredAccess,
            ProcessObjectAttributes,
            ThreadObjectAttributes,
            ProcessFlags,
            ThreadFlags,
            ProcessParameters,
            CreateInfo,
            AttributeList,
        )
    }
}


fn main() {
    unsafe {
        initialize_hooks();
        println!("Hooks initialized!");

        let nt_image_path = U16CString::from_str("\\??\\C:\\Windows\\System32\\calc.exe").unwrap();
        let mut nt_image_path = UNICODE_STRING {
            Length: (nt_image_path.len() * 2) as u16,
            MaximumLength: (nt_image_path.len() * 2) as u16,
            Buffer: nt_image_path.into_raw() as *mut _,
        };

        let mut process_parameters: PRTL_USER_PROCESS_PARAMETERS = null_mut();
        let status = RtlCreateProcessParametersEx(
            &mut process_parameters,
            &mut nt_image_path as *mut _,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            0x01
        );
        shared::check!(status == 0);

        (*process_parameters).WindowFlags |= STARTF_USESHOWWINDOW;
        (*process_parameters).ShowWindowFlags = SW_HIDE as u32;
        
        let mut create_info: PS_CREATE_INFO = core::mem::zeroed();
        create_info.Size = size_of::<PS_CREATE_INFO>();


        let mut attributelist: PS_ATTRIBUTE_LIST = core::mem::zeroed();
        attributelist.TotalLength = size_of::<PS_ATTRIBUTE_LIST>();

        attributelist.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
        attributelist.Attributes[0].Size = nt_image_path.Length as usize;
        attributelist.Attributes[0].u.Value = nt_image_path.Buffer as usize;


        let mut process_handler: HANDLE = null_mut();
        let mut thread_handler: HANDLE = null_mut();

        let stauts = wrp_nt_create_user_process(
            &mut process_handler,
            &mut thread_handler,
            PROCESS_ALL_ACCESS,
            THREAD_ALL_ACCESS,
            null_mut(),
            null_mut(),
            0,
            0,
            process_parameters as *mut _,
            &mut create_info as *mut _,
            &mut attributelist as *mut _,
        );
        println!("NtCreateUserProcess status: {:#X}", stauts);
        shared::utils::breakpoint();
        shared::check!(stauts == 0);

        println!("Process handler: {:#X}", process_handler as usize);


        // Clean up
        RtlDestroyProcessParameters(process_parameters);

        destroy_hooks();
        println!("Hooks destroyed!");
    }
}

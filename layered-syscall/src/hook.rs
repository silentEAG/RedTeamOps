use core::ffi::c_void;
use core::ptr::null_mut;
use std::ptr;

use shared::ntpeb::{ldr_module, NTDLL_HASH};
use windows_sys::Win32::{
    Foundation::{EXCEPTION_ACCESS_VIOLATION, EXCEPTION_SINGLE_STEP},
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, CONTEXT,
            EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
        },
        Memory::{GetProcessHeap, HeapAlloc, HEAP_ZERO_MEMORY},
    },
    UI::WindowsAndMessaging::{MessageBoxA, MB_CANCELTRYCONTINUE, MB_DEFBUTTON2, MB_ICONWARNING},
};

static mut SYSCALL_ENTRY_ADDR: u64 = 0;
static mut SAVED_CONTEXT: *mut CONTEXT = std::ptr::null_mut();
static mut OPCODE_SYSCALL_OFF: u64 = 0;
static mut OPCODE_SYSCALL_RET_OFF: u64 = 0;
static mut IS_SUB_RSP: u8 = 0;
static mut SYSCALL_NO: u64 = 0;
static mut EXTENDED_ARGS: bool = false;
static mut NTDLL_BASE_ADDR: u64 = 0;
static mut NTDLL_END_ADDR: u64 = 0;
static mut H1: *mut c_void = null_mut();
static mut H2: *mut c_void = null_mut();

static OPCODE_SUB_RSP: u32 = 0xec8348;
static OPCODE_RET_CC: u16 = 0xccc3;
static OPCODE_RET: u8 = 0xc3;
static OPCODE_CALL: u8 = 0xe8;
static CALL_FIRST: u32 = 1;
static FIFTH_ARGUMENT: u64 = 0x8 * 0x5;
static SIXTH_ARGUMENT: u64 = 0x8 * 0x6;
static SEVENTH_ARGUMENT: u64 = 0x8 * 0x7;
static EIGHTH_ARGUMENT: u64 = 0x8 * 0x8;
static NINTH_ARGUMENT: u64 = 0x8 * 0x9;
static TENTH_ARGUMENT: u64 = 0x8 * 0xa;
static ELEVENTH_ARGUMENT: u64 = 0x8 * 0xb;
static TWELVETH_ARGUMENT: u64 = 0x8 * 0xc;

fn self_memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            *dest.add(i) = *src.add(i);
        }
    }
    dest
}

pub fn demofunction() {
    unsafe {
        MessageBoxA(
            null_mut(),
            "Hello from demofunction\0".as_ptr(), 
            "Hello\0".as_ptr(),
            MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2,
        );
    }
}

pub unsafe extern "system" fn add_hw_bp(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let exception_record = &mut *(*exception_info).ExceptionRecord;
    let context_record = &mut *(*exception_info).ContextRecord;

    // println!("Rcx: {:x}", context_record.Rcx);
    // println!("{:x}", exception_record.ExceptionCode);

    // println!("(add_hw_bp) Exception Address: {:p}", exception_record.ExceptionAddress);
    // println!("(add_hw_bp) Exception Code: {:x}", exception_record.ExceptionCode);
    // shared::utils::breakpoint();

    if exception_record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION {

        // println!("Access violation exception hit");

        SYSCALL_ENTRY_ADDR = context_record.Rcx;

        // shared::utils::breakpoint();

        for i in 0..25 {
            // find syscall ret opcode offset
            if *((SYSCALL_ENTRY_ADDR + i) as *const u8) == 0x0F && *((SYSCALL_ENTRY_ADDR + i + 1) as *const u8) == 0x05 {
                OPCODE_SYSCALL_OFF = i;
                OPCODE_SYSCALL_RET_OFF = i + 2;
                // println!("Syscall opcode offset: {:x}", OPCODE_SYSCALL_OFF);
                break;
            }
        }

        // Set hwbp at the syscall opcode
        context_record.Dr0 = SYSCALL_ENTRY_ADDR;
        context_record.Dr7 |= 1 << 0;

        // Set hwbp at the syscall ret opcode
        context_record.Dr1 = SYSCALL_ENTRY_ADDR + OPCODE_SYSCALL_RET_OFF;
        context_record.Dr7 |= 1 << 2;

        context_record.Rip += 2;

        // println!("(Dr0) Hardware Breakpoint added at address: {:x}", context_record.Dr0);
        // println!("(Dr1) Hardware Breakpoint added at address: {:x}", context_record.Dr1);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

pub unsafe extern "system" fn handler_hw_bp(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let exception_record = &mut *(*exception_info).ExceptionRecord;
    let context_record = &mut *(*exception_info).ContextRecord;

    // println!("(handler_hw_bp) Exception Address: {:p}", exception_record.ExceptionAddress);
    // println!("(handler_hw_bp) Exception Code: {:x}", exception_record.ExceptionCode);

    if exception_record.ExceptionCode == EXCEPTION_SINGLE_STEP {
        // println!("Single step exception hit");
        // handler for syscall hwbp
        if exception_record.ExceptionAddress == SYSCALL_ENTRY_ADDR as *mut _ {
            // println!("Syscall opcode hit");
            // Clear hwbp
            context_record.Dr0 = 0;
            context_record.Dr7 &= !(1 << 0);
            shared::check!((context_record.Dr7 & 1) == 0);

            // save the registers and clear hwbp
            self_memcpy(
                SAVED_CONTEXT as *mut u8,
                (*exception_info).ContextRecord as *const u8,
                std::mem::size_of::<CONTEXT>(),
            );

            shared::check!((*SAVED_CONTEXT).Dr7 == context_record.Dr7);

            // change RIP to printf()
            context_record.Rip = demofunction as u64;

            // Set the Trace Flag
            context_record.EFlags |= 0x100;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Handler for syscall ret opcode
        else if exception_record.ExceptionAddress
            == (SYSCALL_ENTRY_ADDR + OPCODE_SYSCALL_RET_OFF) as *mut _
        {
            // println!("Syscall ret opcode hit");
            // Clear hwbp
            context_record.Dr1 = 0;
            context_record.Dr7 &= !(1 << 2);

            // change stack so that it can return back to our program
            context_record.Rsp = (*SAVED_CONTEXT).Rsp;

            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // Handler for the Trace flag
        else if context_record.Rip >= NTDLL_BASE_ADDR && context_record.Rip <= NTDLL_END_ADDR {
            // println!("NTDLL hit");

            // println!("Rip: {:x}", context_record.Rip);
            // shared::utils::breakpoint();

            // Find sub rsp, x where x is greater than what you want
            if IS_SUB_RSP == 0 {
                for i in 0..160_u64 {
                    // println!("{}", i);
                    // println!("Rip: {:x}", context_record.Rip);

                    // println!("{:x}", *((context_record.Rip + i) as *const u16));

                    if ptr::read_unaligned((context_record.Rip + i) as *const u16) == OPCODE_RET_CC {
                        // println!("Ret CC found");
                        break;
                    }
                    
                    if ptr::read_unaligned(((context_record.Rip + i)) as *const u32) & 0xffffff == OPCODE_SUB_RSP {
                        if (ptr::read_unaligned((context_record.Rip + i) as *const u32) >> 24) >= 0x58 {
                            // appropriate stack frame found
                            IS_SUB_RSP = 1;
                            // println!("Sub rsp found");
                            context_record.EFlags |= 0x100;
                            return EXCEPTION_CONTINUE_EXECUTION
                        } else {
                            break;
                        }
                    }
                }
            }

            // wait for a call to take place
            if IS_SUB_RSP == 1 {
                // function frame does not contain call instruction
                if ptr::read_unaligned(context_record.Rip as *const u16) == OPCODE_RET_CC
                    || ptr::read_unaligned(context_record.Rip as *const u8) == OPCODE_RET
                {
                    IS_SUB_RSP = 0;
                }
                // function proceeds to perform a call operation
                else if ptr::read_unaligned(context_record.Rip as *const u8) == OPCODE_CALL {
                    IS_SUB_RSP = 2;
                    context_record.EFlags |= 0x100;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            // appropriate stack frame and function frame found
            if IS_SUB_RSP == 2 {
                IS_SUB_RSP = 0;

                let temp_rsp = context_record.Rsp;
                self_memcpy(
                    (*exception_info).ContextRecord as *mut u8,
                    SAVED_CONTEXT as *const u8,
                    core::mem::size_of::<CONTEXT>(),
                );
                context_record.Rsp = temp_rsp;

                // emulate syscall
                // mov r10, rcx
                context_record.R10 = context_record.Rcx;
                // mov rax, #ssn
                context_record.Rax = SYSCALL_NO;
                // set RIP to syscall opcode
                context_record.Rip = SYSCALL_ENTRY_ADDR + OPCODE_SYSCALL_OFF;

                // if >4 args
                if EXTENDED_ARGS {
                    *((context_record.Rsp + FIFTH_ARGUMENT) as *mut u64) = *(((*SAVED_CONTEXT).Rsp + FIFTH_ARGUMENT) as *const u64);
                    *((context_record.Rsp + SIXTH_ARGUMENT) as *mut u64) = *(((*SAVED_CONTEXT).Rsp + SIXTH_ARGUMENT) as *const u64);
                    *((context_record.Rsp + SEVENTH_ARGUMENT) as *mut u64) = *(((*SAVED_CONTEXT).Rsp + SEVENTH_ARGUMENT) as *const u64);
                    *((context_record.Rsp + EIGHTH_ARGUMENT) as *mut u64) = *(((*SAVED_CONTEXT).Rsp + EIGHTH_ARGUMENT) as *const u64);
                    *((context_record.Rsp + NINTH_ARGUMENT) as *mut u64) = *(((*SAVED_CONTEXT).Rsp + NINTH_ARGUMENT) as *const u64);
                    *((context_record.Rsp + TENTH_ARGUMENT) as *mut u64) = *(((*SAVED_CONTEXT).Rsp + TENTH_ARGUMENT) as *const u64);
                    *((context_record.Rsp + ELEVENTH_ARGUMENT) as *mut u64) = *(((*SAVED_CONTEXT).Rsp + ELEVENTH_ARGUMENT) as *const u64);
                    *((context_record.Rsp + TWELVETH_ARGUMENT) as *mut u64) = *(((*SAVED_CONTEXT).Rsp + TWELVETH_ARGUMENT) as *const u64);
                }

                // Clear Trace Flag
                context_record.EFlags &= !0x100;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // continue tracing
        context_record.EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

pub unsafe fn initialize_hooks() {
    H1 = AddVectoredExceptionHandler(CALL_FIRST, Some(add_hw_bp));
    H2 = AddVectoredExceptionHandler(CALL_FIRST, Some(handler_hw_bp));

    SAVED_CONTEXT =
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size_of::<CONTEXT>()) as *mut CONTEXT;

    // println!("Saved Context: {:p}", SAVED_CONTEXT);

    let ntdll = ldr_module(NTDLL_HASH);

    NTDLL_BASE_ADDR = (*ntdll).DllBase as u64;
    NTDLL_END_ADDR = NTDLL_BASE_ADDR + (*ntdll).SizeOfImage as u64;
}

pub unsafe fn destroy_hooks() {
    RemoveVectoredExceptionHandler(H1);
    RemoveVectoredExceptionHandler(H2);
}

pub fn set_hw_bp(func_address: u64, flag: bool, ssn: u16) {
    unsafe {
        EXTENDED_ARGS = flag;
        SYSCALL_NO = ssn as u64;
    }
    // println!("Triggering exception");
    _set_hw_bp(func_address);
}

fn _set_hw_bp(_func_address: u64) {
    // trigger the access violation exception
    unsafe {
        
        let a = null_mut();
        let _b: i32 = *a;
    }
}

// #[test]
// fn test_trigger_exception() {
//     unsafe {
//         demofunction();
//     }
// }

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Philipp Schulz <schulz.phil@gmx.de>
// Copyright (c) 2024 Dinu Blanovschi <dinu@dnbln.dev>

//! AArch32.

use crate::QEMUExit;
use core::arch::asm;

fn sh_feature_supported(bytenum: i32, bitnum: i32) -> bool {
    fn sys_open(name: &[u8], mode: i32) -> i32 {
        #[repr(C)]
        struct SysOpenParameterBlock {
            ptr: *const u8,
            mode: i32,
            len: i32,
        }

        let name_ptr = name.as_ptr();
        let name_len = name.len();
        let name_len = name_len as i32 - 1; // Remove the null terminator
        let mode = mode as i32;
        let pb = SysOpenParameterBlock {
            ptr: name_ptr,
            mode,
            len: name_len,
        };
        let ret: i32;
        unsafe {
            asm!(
                "bkpt #0xab",
                in("r0") 0x01,
                in("r1") &pb as *const _ as u32,
                lateout("r0") ret,
                options(nostack)
            );
        }
        ret
    }

    fn sys_flen(fh: i32) -> i32 {
        #[repr(C)]
        struct SysFlenParameterBlock {
            fh: i32,
        }

        let pb = SysFlenParameterBlock { fh };
        let ret: i32;
        unsafe {
            asm!(
                "bkpt #0xab",
                in("r0") 0x0C,
                in("r1") &pb as *const _ as u32,
                lateout("r0") ret,
                options(nostack)
            );
        }
        ret
    }

    fn sys_seek(fh: i32, pos: i32) -> i32 {
        #[repr(C)]
        struct SysSeekParameterBlock {
            fh: i32,
            pos: i32,
        }

        let pb = SysSeekParameterBlock { fh, pos };
        let ret: i32;
        unsafe {
            asm!(
                "bkpt #0xab",
                in("r0") 0x0A,
                in("r1") &pb as *const _ as u32,
                lateout("r0") ret,
                options(nostack)
            );
        }
        ret
    }

    fn sys_read(fh: i32, buf: &mut [u8]) -> i32 {
        #[repr(C)]
        struct SysReadParameterBlock {
            fh: i32,
            buf: *mut u8,
            len: i32,
        }

        let buf_ptr = buf.as_mut_ptr();
        let buf_len = buf.len();
        let buf_len = buf_len as i32;

        let pb = SysReadParameterBlock {
            fh,
            buf: buf_ptr as *mut u8,
            len: buf_len,
        };
        let ret: i32;
        unsafe {
            asm!(
                "bkpt #0xab",
                in("r0") 0x06,
                in("r1") &pb as *const _ as u32,
                lateout("r0") ret,
                options(nostack)
            );
        }
        ret
    }

    fn sys_close(fh: i32) -> i32 {
        #[repr(C)]
        struct SysCloseParameterBlock {
            fh: i32,
        }

        let pb = SysCloseParameterBlock { fh };
        let ret: i32;
        unsafe {
            asm!(
                "bkpt #0xab",
                in("r0") 0x02,
                in("r1") &pb as *const _ as u32,
                lateout("r0") ret,
                options(nostack)
            );
        }
        ret
    }

    const MAGICLEN: usize = 4;
    const SHFB_MAGIC_0: u8 = 0x53;
    const SHFB_MAGIC_1: u8 = 0x48;
    const SHFB_MAGIC_2: u8 = 0x46;
    const SHFB_MAGIC_3: u8 = 0x42;

    let mut magic = [0_u8; MAGICLEN];
    let mut c = [0_u8; 1];
    let fh: i32;
    let len: i32;

    fh = sys_open(b":semihosting-features\0", 0);
    if fh == -1 {
        return false;
    }
    len = sys_flen(fh);
    if len <= bytenum {
        sys_close(fh);
        return false;
    }
    if sys_read(fh, &mut magic) != 0 {
        sys_close(fh);
        return false;
    }
    if magic[0] != SHFB_MAGIC_0
        || magic[1] != SHFB_MAGIC_1
        || magic[2] != SHFB_MAGIC_2
        || magic[3] != SHFB_MAGIC_3
    {
        sys_close(fh);
        return false;
    }
    if sys_seek(fh, bytenum) != 0 {
        sys_close(fh);
        return false;
    }
    if sys_read(fh, &mut c) != 0 {
        sys_close(fh);
        return false;
    }
    sys_close(fh);
    return (c[0] & (1 << bitnum)) != 0;
}

fn exit_extended_supported() -> bool {
    sh_feature_supported(0, 0)
}

const EXIT_SUCCESS: u32 = 0;
const EXIT_FAILURE: u32 = 1;

#[allow(non_upper_case_globals)]
const ADP_Stopped_ApplicationExit: u32 = 0x20026;

/// The parameter block layout that is expected by QEMU.
///
/// If QEMU finds `ADP_Stopped_ApplicationExit` in the first parameter, it uses the second parameter
/// as exit code.
///
/// If first paraemter != `ADP_Stopped_ApplicationExit`, exit code `1` is used.
#[repr(C)]
struct QEMUParameterBlock {
    arg0: u32,
    arg1: u32,
}

/// AArch32 configuration.
pub struct AArch32 {}

/// A Semihosting call using `0x20` - `SYS_EXIT_EXTENDED`.
fn semihosting_sys_exit_extended_call(block: &QEMUParameterBlock) -> ! {
    unsafe {
        asm!(
            "bkpt #0xab",
            in("r0") 0x20,
            in("r1") block as *const _ as u32,
            options(nostack)
        );

        // For the case that the QEMU exit attempt did not work, transition into an infinite loop.
        // Calling `panic!()` here is unfeasible, since there is a good chance this function here is
        // the last expression in the `panic!()` handler itself. This prevents a possible
        // infinite loop.
        loop {
            asm!("wfe", options(nomem, nostack));
        }
    }
}

fn semihosting_sys_exit_call(block: &QEMUParameterBlock) -> ! {
    unsafe {
        asm!(
            "bkpt #0xab",
            in("r0") 0x18,
            in("r1") block as *const _ as u32,
            options(nostack)
        );

        // For the case that the QEMU exit attempt did not work, transition into an infinite loop.
        // Calling `panic!()` here is unfeasible, since there is a good chance this function here is
        // the last expression in the `panic!()` handler itself. This prevents a possible
        // infinite loop.
        loop {
            asm!("wfe", options(nomem, nostack));
        }
    }
}

impl AArch32 {
    /// Create an instance.
    pub const fn new() -> Self {
        AArch32 {}
    }
}

impl QEMUExit for AArch32 {
    fn exit(&self, code: u32) -> ! {
        let block = QEMUParameterBlock {
            arg0: ADP_Stopped_ApplicationExit,
            arg1: code as u32,
        };

        if exit_extended_supported() {
            semihosting_sys_exit_extended_call(&block)
        } else {
            semihosting_sys_exit_call(&block)
        }
    }

    fn exit_success(&self) -> ! {
        self.exit(EXIT_SUCCESS)
    }

    fn exit_failure(&self) -> ! {
        self.exit(EXIT_FAILURE)
    }
}

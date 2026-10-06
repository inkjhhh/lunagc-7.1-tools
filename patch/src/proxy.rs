//! forwards the dbghelp exports to the real System32 dbghelp.dll

use std::ffi::CString;

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

include!(concat!(env!("OUT_DIR"), "/export_proxy.rs"));

/// stub for exports the real dll lacks
unsafe extern "C" fn missing() -> usize {
    0
}

/// fills the table from %SystemRoot%\System32\dbghelp.dll
pub unsafe fn init() {
    // seed first, so no slot is ever 0
    let stub = missing as unsafe extern "C" fn() -> usize as usize;
    for slot in (&raw mut REAL).as_mut().unwrap() {
        *slot = stub;
    }

    let sysroot =
        std::env::var("SystemRoot").unwrap_or_else(|_| String::from(r"C:\Windows"));
    let target = format!("{sysroot}\\System32\\dbghelp.dll");
    let path: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();

    let real = match LoadLibraryW(PCWSTR(path.as_ptr())) {
        Ok(handle) => handle,
        Err(e) => {
            crate::plog!("[proxy] could not load {target}: {e}");
            return;
        }
    };

    let mut resolved = 0;
    for (i, name) in NAMES.iter().enumerate() {
        let c_name = CString::new(*name).unwrap();
        if let Some(addr) = GetProcAddress(real, PCSTR(c_name.as_ptr() as *const u8)) {
            REAL[i] = addr as usize;
            resolved += 1;
        } else {
            crate::plog!("[proxy] real dbghelp does not export {name}");
        }
    }

    crate::plog!(
        "[proxy] forwarding {}/{} dbghelp exports to System32",
        resolved,
        NAMES.len()
    );
    let _: HMODULE = real;
}

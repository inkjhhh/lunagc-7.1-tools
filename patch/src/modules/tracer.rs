//! Traces the (2,0,4) "client is damaged" dialog back to its caller.
//!
//! Strategy: hook MessageBoxW/A + process-exit APIs, log the dialog text
//! plus the return address as module+RVA. The RVA is then mapped offline
//! with objdump to find the integrity-check branch that triggers it.

use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;
use std::ffi::c_void;
use windows::{
    core::s,
    Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
};

#[link(name = "kernel32")]
extern "system" {
    fn AddVectoredExceptionHandler(first: u32, handler: *const c_void) -> *mut c_void;
}

const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

pub struct Tracer;

impl MhyModule for MhyContext<Tracer> {
    unsafe fn init(&mut self) -> Result<()> {
        hook_one(&mut self.interceptor, "user32.dll", "MessageBoxW", on_messageboxw);
        hook_one(
            &mut self.interceptor,
            "user32.dll",
            "MessageBoxExW",
            on_messageboxw,
        );
        hook_one(&mut self.interceptor, "user32.dll", "MessageBoxA", on_messageboxa);
        hook_one(
            &mut self.interceptor,
            "user32.dll",
            "MessageBoxExA",
            on_messageboxa,
        );
        hook_one(
            &mut self.interceptor,
            "kernel32.dll",
            "ExitProcess",
            on_exitprocess,
        );
        hook_one(
            &mut self.interceptor,
            "kernel32.dll",
            "TerminateProcess",
            on_terminateprocess,
        );
        hook_one(
            &mut self.interceptor,
            "comctl32.dll",
            "TaskDialogIndirect",
            on_taskdialogindirect,
        );
        hook_one(
            &mut self.interceptor,
            "user32.dll",
            "DialogBoxParamW",
            on_dialogboxparamw,
        );
        hook_one(
            &mut self.interceptor,
            "user32.dll",
            "MessageBoxIndirectW",
            on_messageboxindirectw,
        );
        hook_one(
            &mut self.interceptor,
            "user32.dll",
            "CreateWindowExW",
            on_createwindowexw,
        );
        hook_one(
            &mut self.interceptor,
            "ntdll.dll",
            "NtTerminateProcess",
            on_ntterminateprocess,
        );
        for crt in ["ucrtbase.dll", "msvcrt.dll"] {
            hook_one(&mut self.interceptor, crt, "abort", on_abort);
        }
        hook_one(
            &mut self.interceptor,
            "kernel32.dll",
            "EnumProcessModules",
            on_enumprocessmodules,
        );
        hook_one(
            &mut self.interceptor,
            "kernel32.dll",
            "K32EnumProcessModules",
            on_enumprocessmodules,
        );
        hook_one(
            &mut self.interceptor,
            "kernel32.dll",
            "CreateToolhelp32Snapshot",
            on_createtoolhelp,
        );
        hook_one(
            &mut self.interceptor,
            "kernel32.dll",
            "Module32FirstW",
            on_module32firstnext,
        );
        hook_one(
            &mut self.interceptor,
            "kernel32.dll",
            "Module32NextW",
            on_module32firstnext,
        );
        // wintrust may load later (with mhypbase) - poll for it
        std::thread::spawn(|| unsafe { late_verify_hook() });
        dump_module_map();
        dump_fault_region();
        unsafe {
            AddVectoredExceptionHandler(1, vehicular as *const c_void);
        }
        crate::plog!("[tracer] VEH fault logger installed");
        crate::plog!("[tracer] hooks installed");
        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Tracer
    }
}

unsafe fn hook_one(
    interceptor: &mut crate::interceptor::Interceptor,
    dll: &str,
    func: &str,
    routine: ilhook::x64::JmpBackRoutine,
) {
    let dll_c = std::ffi::CString::new(dll).unwrap();
    let func_c = std::ffi::CString::new(func).unwrap();
    let dll_pc = windows::core::PCSTR(dll_c.as_ptr() as *const u8);
    let func_pc = windows::core::PCSTR(func_c.as_ptr() as *const u8);
    let h = match GetModuleHandleA(dll_pc) {
        Ok(h) => h,
        Err(e) => {
            crate::plog!("[tracer] no handle for {}: {:?}", dll, e);
            return;
        }
    };
    let addr = match GetProcAddress(h, func_pc) {
        Some(f) => f as usize,
        None => {
            crate::plog!("[tracer] no proc {}.{}", dll, func);
            return;
        }
    };
    match interceptor.attach(addr, routine) {
        Ok(()) => crate::plog!("[tracer] hooked {}.{} at 0x{:X}", dll, func, addr),
        Err(e) => crate::plog!("[tracer] hook failed {}.{}: {:?}", dll, func, e),
    }
}

/// Read a NUL-terminated UTF-16 string from this process without crashing
/// on bad pointers (uses ReadProcessMemory which fails gracefully).
unsafe fn read_wide(ptr: u64) -> String {
    use winapi::shared::minwindef::{LPCVOID, LPVOID};
    use winapi::um::winnt::HANDLE;
    if ptr == 0 {
        return String::from("<null>");
    }
    let mut buf = [0u16; 256];
    let mut read: usize = 0;
    let ok = winapi::um::memoryapi::ReadProcessMemory(
        (-1isize) as HANDLE,
        ptr as LPCVOID,
        buf.as_mut_ptr() as LPVOID,
        512,
        &mut read,
    );
    if ok == 0 {
        return String::from("<unreadable>");
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

unsafe fn read_ansi(ptr: u64) -> String {
    use winapi::shared::minwindef::{LPCVOID, LPVOID};
    use winapi::um::winnt::HANDLE;
    if ptr == 0 {
        return String::from("<null>");
    }
    let mut buf = [0u8; 256];
    let mut read: usize = 0;
    let ok = winapi::um::memoryapi::ReadProcessMemory(
        (-1isize) as HANDLE,
        ptr as LPCVOID,
        buf.as_mut_ptr() as LPVOID,
        256,
        &mut read,
    );
    if ok == 0 {
        return String::from("<unreadable>");
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

/// Resolve an address to (module file name, module base, RVA).
pub(crate) unsafe fn resolve(addr: u64) -> (String, usize, usize) {
    use winapi::shared::minwindef::{DWORD, HMODULE, LPCVOID};
    use winapi::um::winnt::MEMORY_BASIC_INFORMATION;
    use winapi::um::memoryapi::VirtualQuery;
    let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    let q = VirtualQuery(
        addr as LPCVOID,
        &mut mbi,
        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
    );
    if q == 0 {
        return (String::from("<unknown>"), 0, addr as usize);
    }
    let base = mbi.AllocationBase as usize;
    let mut buf = [0u16; 260];
    let len: DWORD = winapi::um::libloaderapi::GetModuleFileNameW(
        base as HMODULE,
        buf.as_mut_ptr(),
        260,
    );
    let name = if len == 0 {
        String::from("<noname>")
    } else {
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        s.rsplit(['\\', '/']).next().unwrap_or(&s).to_string()
    };
    (name, base, (addr as usize).wrapping_sub(base))
}

unsafe fn log_stack(reg: *mut Registers, depth: usize) {
    let mut st = String::from("[tracer] stack:");
    for i in 0..depth {
        st.push_str(&format!(" 0x{:X}", (*reg).get_stack(i)));
    }
    crate::plog!("{}", st);
}

// MessageBoxW(HWND, LPCWSTR text, LPCWSTR caption, UINT type)
unsafe extern "win64" fn on_messageboxw(reg: *mut Registers, _: usize) {
    let text = read_wide((*reg).rdx);
    let caption = read_wide((*reg).r8);
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] MessageBoxW text=\"{}\" caption=\"{}\" ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        text,
        caption,
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 10);
}

// MessageBoxA(HWND, LPCSTR text, LPCSTR caption, UINT type)
unsafe extern "win64" fn on_messageboxa(reg: *mut Registers, _: usize) {
    let text = read_ansi((*reg).rdx);
    let caption = read_ansi((*reg).r8);
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] MessageBoxA text=\"{}\" caption=\"{}\" ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        text,
        caption,
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 10);
}

// ExitProcess(UINT code): rcx = exit code
unsafe extern "win64" fn on_exitprocess(reg: *mut Registers, _: usize) {
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] ExitProcess code={} ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        (*reg).rcx,
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 10);
}

// TaskDialogIndirect(const TASKDIALOGCONFIG*, ...): rcx = config.
// x64 TASKDIALOGCONFIG layout: pszWindowTitle at +32, pszContent at +56.
unsafe extern "win64" fn on_taskdialogindirect(reg: *mut Registers, _: usize) {
    let cfg = (*reg).rcx;
    let (title, content) = if cfg == 0 {
        (String::from("<null>"), String::from("<null>"))
    } else {
        let t = read_ptr_wide(cfg.wrapping_add(32));
        let c = read_ptr_wide(cfg.wrapping_add(56));
        (t, c)
    };
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] TaskDialogIndirect title=\"{}\" content=\"{}\" ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        title,
        content,
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 10);
}

unsafe fn read_ptr_wide(field_addr: u64) -> String {
    use winapi::shared::minwindef::{LPCVOID, LPVOID};
    let mut ptr: u64 = 0;
    let mut read: usize = 0;
    let ok = winapi::um::memoryapi::ReadProcessMemory(
        (-1isize) as winapi::um::winnt::HANDLE,
        field_addr as LPCVOID,
        (&mut ptr as *mut u64) as LPVOID,
        8,
        &mut read,
    );
    if ok == 0 {
        return String::from("<unreadable>");
    }
    read_wide(ptr)
}

// wintrust.dll arrives later with mhypbase; poll until it appears, then
// hook WinVerifyTrust. Keeps its own Interceptor alive via mem::forget.
unsafe fn late_verify_hook() {
    let mut interceptor = crate::interceptor::Interceptor::new();
    for _ in 0..150 {
        let dll_c = std::ffi::CString::new("wintrust.dll").unwrap();
        let dll_pc = windows::core::PCSTR(dll_c.as_ptr() as *const u8);
        if GetModuleHandleA(dll_pc).is_ok() {
            hook_replace_one(
                &mut interceptor,
                "wintrust.dll",
                "WinVerifyTrust",
                on_winverifytrust_lie,
            );
            crate::plog!("[tracer] late WinVerifyTrust LIE installed");
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    std::mem::forget(interceptor);
}

// Logs every MEM_IMAGE region (module base + size + file name) once at
// startup, so a later fault address can be mapped to module+RVA offline.
unsafe fn dump_module_map() {
    use winapi::shared::minwindef::LPCVOID;
    use winapi::um::memoryapi::VirtualQuery;
    use winapi::um::winnt::MEMORY_BASIC_INFORMATION;
    const MEM_IMAGE: u32 = 0x1000000;
    let mut addr: usize = 0x10000;
    let mut last_base: usize = 0;
    let mut count = 0;
    while addr < 0x7FFFFFFF0000 && count < 400 {
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let q = VirtualQuery(
            addr as LPCVOID,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        if q == 0 {
            break;
        }
        let size = mbi.RegionSize as usize;
        if mbi.Type == MEM_IMAGE && (mbi.AllocationBase as usize) != last_base {
            last_base = mbi.AllocationBase as usize;
            let mut buf = [0u16; 260];
            let len = winapi::um::libloaderapi::GetModuleFileNameW(
                last_base as winapi::shared::minwindef::HMODULE,
                buf.as_mut_ptr(),
                260,
            );
            let name = if len == 0 {
                String::from("<noname>")
            } else {
                let s = String::from_utf16_lossy(&buf[..len as usize]);
                s.rsplit(['\\', '/']).next().unwrap_or(&s).to_string()
            };
            // region size for this base: walk is per-region, accumulate below
            crate::plog!("[tracer] modmap base=0x{:X} name={}", last_base, name);
            count += 1;
        }
        if size == 0 {
            break;
        }
        addr += size;
    }
    crate::plog!("[tracer] modmap done, {} modules", count);
}

// Dumps 128KB of MHYPBase code around the known fault RVA 0x18F8BAE
// straight from memory (already unpacked by UPX at this point).
// Static objdump of the file is useless because of the .upx0 packing.
unsafe fn dump_fault_region() {
    const FAULT_RVA: usize = 0x18F8BAE;
    const HALF: usize = 0x10000;
    let dll_c = std::ffi::CString::new("mhypbase.dll").unwrap();
    let dll_pc = windows::core::PCSTR(dll_c.as_ptr() as *const u8);
    let base = match GetModuleHandleA(dll_pc) {
        Ok(h) => h.0 as usize,
        Err(_) => {
            crate::plog!("[tracer] dump: no mhypbase handle yet");
            return;
        }
    };
    let start = base.wrapping_add(FAULT_RVA.wrapping_sub(HALF));
    let bytes = HALF * 2;
    let mut buf = vec![0u8; bytes];
    std::ptr::copy_nonoverlapping(start as *const u8, buf.as_mut_ptr(), bytes);
    let path = std::env::temp_dir().join("mhyp_fault.bin");
    if std::fs::write(&path, &buf).is_ok() {
        crate::plog!(
            "[tracer] dump: wrote {} bytes from mhypbase+0x{:X} to {}",
            bytes,
            FAULT_RVA - HALF,
            path.display()
        );
    } else {
        crate::plog!("[tracer] dump: write failed");
    }
}

// Vectored Exception Handler: logs fault code + fault address, then lets
// WER continue. Runs only when a fault has ALREADY happened, so it cannot
// cause the crash itself.
unsafe extern "system" fn vehicular(info: *mut c_void) -> i32 {
    if info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let record = *(info as *const usize) as usize;
    if record == 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let code = *(record as *const u32);
    let fault = *((record as usize).wrapping_add(16) as *const usize);
    let (modname, base, rva) = resolve(fault as u64);
    crate::plog!(
        "[tracer] FAULT code=0x{:X} addr=0x{:X} {}+0x{:X} (base=0x{:X})",
        code,
        fault,
        modname,
        rva,
        base
    );
    EXCEPTION_CONTINUE_SEARCH
}
unsafe extern "win64" fn on_messageboxindirectw(reg: *mut Registers, _: usize) {
    let p = (*reg).rcx;
    let (text, caption) = if p == 0 {
        (String::from("<null>"), String::from("<null>"))
    } else {
        (read_ptr_wide(p.wrapping_add(16)), read_ptr_wide(p.wrapping_add(32)))
    };
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] MessageBoxIndirectW text=\"{}\" caption=\"{}\" ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        text,
        caption,
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 10);
}

// CreateWindowExW(..., lpClassName=rdx, lpWindowName=r8, ...).
// Only log dialog-class windows (#32770) to avoid flooding.
unsafe extern "win64" fn on_createwindowexw(reg: *mut Registers, _: usize) {
    let cls = (*reg).rdx;
    if cls == 0 {
        return;
    }
    let is_dialog = if cls <= 0xFFFF {
        false
    } else {
        read_wide(cls) == "#32770"
    };
    if !is_dialog {
        return;
    }
    let title = read_wide((*reg).r8);
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] CreateWindowExW#32770 title=\"{}\" ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        title,
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 10);
}

// NtTerminateProcess(HANDLE, NTSTATUS): catches every user-mode kill path,
// including CRT abort()/exit() and direct syscalls that bypass kernel32.
unsafe extern "win64" fn on_ntterminateprocess(reg: *mut Registers, _: usize) {
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] NtTerminateProcess handle=0x{:X} code=0x{:X} ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        (*reg).rcx,
        (*reg).rdx,
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 12);
}

// abort(void): no args.
unsafe extern "win64" fn on_abort(reg: *mut Registers, _: usize) {
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] abort() ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 12);
}
// rdx = template (int resource if value <= 0xFFFF, else string).
unsafe extern "win64" fn on_dialogboxparamw(reg: *mut Registers, _: usize) {
    let tpl = (*reg).rdx;
    let desc = if tpl <= 0xFFFF {
        format!("#{}", tpl)
    } else {
        read_wide(tpl)
    };
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] DialogBoxParamW template=\"{}\" ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        desc,
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 10);
}
unsafe extern "win64" fn on_terminateprocess(reg: *mut Registers, _: usize) {
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] TerminateProcess handle=0x{:X} code={} ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        (*reg).rcx,
        (*reg).rdx,
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 10);
}

// WinVerifyTrust(HWND, GUID* action, WINTRUST_DATA* data): rcx, rdx, r8.
// WINTRUST_DATA.pFile at +40 -> WINTRUST_FILE_INFO.pcwszFilePath at +8.
unsafe extern "win64" fn on_winverifytrust(reg: *mut Registers, _: usize) {
    let data = (*reg).r8;
    let file = if data == 0 {
        String::from("<null-data>")
    } else {
        let pfile = unsafe_read_usize(data.wrapping_add(40));
        if pfile == 0 {
            String::from("<null-pfile>")
        } else {
            read_wide(unsafe_read_usize(pfile.wrapping_add(8)))
        }
    };
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] WinVerifyTrust file=\"{}\" ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        file,
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 8);
}

unsafe fn hook_replace_one(
    interceptor: &mut crate::interceptor::Interceptor,
    dll: &str,
    func: &str,
    routine: ilhook::x64::RetnRoutine,
) {
    let dll_c = std::ffi::CString::new(dll).unwrap();
    let func_c = std::ffi::CString::new(func).unwrap();
    let dll_pc = windows::core::PCSTR(dll_c.as_ptr() as *const u8);
    let func_pc = windows::core::PCSTR(func_c.as_ptr() as *const u8);
    let h = match GetModuleHandleA(dll_pc) {
        Ok(h) => h,
        Err(e) => {
            crate::plog!("[tracer] no handle for {}: {:?}", dll, e);
            return;
        }
    };
    // NOTE: in this windows version GetProcAddress returns Option
    let addr = match GetProcAddress(h, func_pc) {
        Some(f) => f as usize,
        None => {
            crate::plog!("[tracer] no proc {}.{}", dll, func);
            return;
        }
    };
    match interceptor.replace(addr, routine) {
        Ok(()) => crate::plog!("[tracer] replaced {}.{} at 0x{:X}", dll, func, addr),
        Err(e) => crate::plog!("[tracer] replace failed {}.{}: {:?}", dll, func, e),
    }
}

// Selective lie: files under the game dir always verify OK, everything
// else goes to the real WinVerifyTrust.
unsafe extern "win64" fn on_winverifytrust_lie(
    reg: *mut Registers,
    ori: usize,
    _: usize,
) -> usize {
    let data = (*reg).r8;
    let mut game_file = false;
    let mut desc = String::from("<null-data>");
    if data != 0 {
        let pfile = unsafe_read_usize(data.wrapping_add(40));
        if pfile != 0 {
            let f = read_wide(unsafe_read_usize(pfile.wrapping_add(8)));
            desc = f.clone();
            let lower = f.to_lowercase();
            game_file = lower.contains("genshin impact game")
                || lower.contains("dbghelp")
                || lower.contains("astrolabe")
                || lower.contains("mhypbase")
                || lower.contains("yuanshen");
        }
    }
    if game_file {
        crate::plog!("[tracer] WinVerifyTrust LIE ok for \"{}\"", desc);
        return 0; // ERROR_SUCCESS
    }
    type WVT = unsafe extern "system" fn(isize, *const u8, *mut u8) -> i32;
    let r = (std::mem::transmute::<usize, WVT>(ori))(
        (*reg).rcx as isize,
        (*reg).rdx as *const u8,
        (*reg).r8 as *mut u8,
    );
    r as usize
}

unsafe fn unsafe_read_usize(addr: u64) -> u64 {
    if addr == 0 {
        return 0;
    }
    *(addr as *const u64)
}

// EnumProcessModules(HANDLE, HMODULE*, DWORD, LPDWORD): just log caller.
unsafe extern "win64" fn on_enumprocessmodules(reg: *mut Registers, _: usize) {
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] EnumProcessModules ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 6);
}

// CreateToolhelp32Snapshot(DWORD, DWORD): rcx = flags.
unsafe extern "win64" fn on_createtoolhelp(reg: *mut Registers, _: usize) {
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] CreateToolhelp32Snapshot flags=0x{:X} ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        (*reg).rcx,
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 6);
}

unsafe extern "win64" fn on_module32firstnext(reg: *mut Registers, _: usize) {
    let ret = (*reg).get_stack(0);
    let (modname, base, rva) = resolve(ret);
    crate::plog!(
        "[tracer] Module32First/Next ret=0x{:X} {}+0x{:X} (base=0x{:X})",
        ret,
        modname,
        rva,
        base
    );
    log_stack(reg, 6);
}

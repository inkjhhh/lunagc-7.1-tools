#![feature(str_from_utf16_endian)]

// v1 experiment: pure export proxy + Tracer (dialog/exit/verify/enum hooks).
// NO crypto hooks, NO memprotect tampering - isolates the MDK trigger.

use lazy_static::lazy_static;
use std::sync::RwLock;
use windows::Win32::System::Console;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::{Foundation::HINSTANCE, System::LibraryLoader::GetModuleFileNameA};
use std::ffi::CStr;
use std::path::Path;

mod log;
mod proxy;
mod interceptor;
mod marshal;
mod modules;
mod util;

use crate::modules::{CcpBlocker, Http, MhyContext, Misc, ModuleManager, Security, Tracer, WinHttp};

unsafe fn thread_func() {
    let mut module_manager = MODULE_MANAGER.write().unwrap();

    // Tracer first: dialog/exit/verify hooks before anything fires
    module_manager.enable(MhyContext::<Tracer>::new(""));

    Console::AllocConsole().unwrap();

    crate::plog!("dbghelp proxy loaded (v2, full)");

    let mut buffer = [0u8; 260];
    GetModuleFileNameA(None, &mut buffer);
    let exe_path = CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap();
    let exe_name = Path::new(exe_path).file_name().unwrap().to_str().unwrap();
    crate::plog!("Current executable name: {}", exe_name);

    if exe_name != "GenshinImpact.exe" && exe_name != "YuanShen.exe" {
        crate::plog!("Executable is not Genshin. Skipping initialization.");
        return;
    }

    crate::plog!("Initializing crypto modules...");

    // Block query_security_file ASAP
    module_manager.enable(MhyContext::<CcpBlocker>::new(""));

    util::disable_memprotect_guard();

    module_manager.enable(MhyContext::<Security>::new(exe_name));
    marshal::find();
    module_manager.enable(MhyContext::<Http>::new(exe_name));
    module_manager.enable(MhyContext::<Misc>::new(exe_name));

    // the account sdk uses winhttp, not the C# path above
    module_manager.enable(MhyContext::<WinHttp>::new(exe_name));

    crate::plog!("Successfully initialized!");
}

lazy_static! {
    static ref MODULE_MANAGER: RwLock<ModuleManager> = RwLock::new(ModuleManager::default());
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        log::start_session();

        // here, not on the thread: the game may call the exports once DllMain returns
        proxy::init();

        #[cfg(debug_assertions)]
        {
            thread_func();
        }
        #[cfg(not(debug_assertions))]
        {
            std::thread::spawn(|| thread_func());
        }
    }

    true
}

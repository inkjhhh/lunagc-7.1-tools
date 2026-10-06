use std::ffi::CStr;

use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;
use windows::{
    core::s,
    Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
};

pub struct CcpBlocker;

impl MhyModule for MhyContext<CcpBlocker> {
    unsafe fn init(&mut self) -> Result<()> {
        let winsock2 = GetModuleHandleA(s!("Ws2_32.dll")).unwrap();
        let getaddrinfo = GetProcAddress(winsock2, s!("getaddrinfo")).unwrap();

        self.interceptor
            .attach(getaddrinfo as usize, on_getaddrinfo)
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::CcpBlocker
    }
}

unsafe extern "win64" fn on_getaddrinfo(reg: *mut Registers, _: usize) {
    let host_ptr = (*reg).rcx as *const i8;
    // a null nodename is legal
    if host_ptr.is_null() {
        return;
    }
    let host = CStr::from_ptr(host_ptr).to_string_lossy();

    if host == "dispatchosglobal.yuanshen.com" || host == "dispatchcnglobal.yuanshen.com" {
        std::ptr::copy_nonoverlapping(c"0.0.0.0".as_ptr(), (*reg).rcx as *mut i8, 9);
        return;
    }

    // SDK hosts used by the bundled curl stack (loginByPassword etc.).
    // The curl path is NOT covered by the http.rs/winhttp.rs rewrites, so
    // point it at the local TLS front (127.0.0.1:443) which forwards to
    // the dispatch server. Replacement is shorter than any hostname.
    if host == "passport-api.mihoyo.com"
        || host == "passport-api.miyoushe.com"
        || host == "hk4e-sdk-s.mihoyo.com"
        || host == "hk4e-sdk.mihoyo.com"
        || host == "sdk-static.mihoyo.com"
        || host == "public-data-api.mihoyo.com"
        || host == "data-abtest-api.mihoyo.com"
    {
        crate::plog!("[dns] {} -> 127.0.0.1", host);
        std::ptr::copy_nonoverlapping(c"127.0.0.1".as_ptr(), (*reg).rcx as *mut i8, 10);
    }
}

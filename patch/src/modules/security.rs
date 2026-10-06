use std::ffi::CString;

use crate::marshal;

use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;
use crate::util;

const MHYRSA_PERFORM_CRYPTO_ACTION: &str = "E8 ? ? ? ? 48 83 C4 20 66 41 C7 06 30 82";
const KEY_SIGN_CHECK: &str = "E8 ? ? ? ? 48 83 C4 30 84 C0 74 ? 41 8B 04 24";
const KEY_SIGN_CHECK_OFFSET: usize = 0x5;
const SDK_UTIL_RSA_ENCRYPT: &str = "41 57 41 56 41 55 41 54 56 57 55 53 48 83 EC ?? 49 89 D6 48 89 CE 48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 49 89 C5";

const KEY_SIZE: usize = 268;
static SERVER_PUBLIC_KEY: &[u8] = include_bytes!("../../server_public_key.bin");
static SDK_PUBLIC_KEY: &str = include_str!("../../sdk_public_key.xml");

pub struct Security;

unsafe fn module_present(name: &str) -> bool {
    let c = std::ffi::CString::new(name).unwrap();
    let pc = windows::core::PCSTR(c.as_ptr() as *const u8);
    use windows::Win32::System::LibraryLoader::GetModuleHandleA;
    GetModuleHandleA(pc).is_ok()
}

unsafe fn scan_extra(interceptor: &mut crate::interceptor::Interceptor, extra: &str) {
    if !module_present(extra) {
        crate::plog!("scan: {} not loaded, skip", extra);
        return;
    }
    if let Some(addr) = util::pattern_scan_code(extra, MHYRSA_PERFORM_CRYPTO_ACTION) {
        crate::plog!("{} mhyrsa_perform_crypto_action: {:x}", extra, addr as usize);
        let _ = interceptor.attach(addr as usize, on_mhy_rsa);
    }
    if let Some(addr) = util::pattern_scan_code(extra, KEY_SIGN_CHECK) {
        let off = addr as usize + KEY_SIGN_CHECK_OFFSET;
        crate::plog!("{} key_sign_check: {:x}", extra, off);
        let _ = interceptor.attach(off, after_key_sign_check);
    }
    if let Some(addr) = util::pattern_scan_code(extra, SDK_UTIL_RSA_ENCRYPT) {
        crate::plog!("{} sdk_util_rsa_encrypt: {:x}", extra, addr as usize);
        let _ = interceptor.attach(addr as usize, on_sdk_util_rsa_encrypt);
    }
}

/// HoYoChannel.dll loads lazily at login time - poll until it appears, then
/// scan it. Own Interceptor kept alive via mem::forget.
unsafe fn late_crypto_scan() {
    let mut interceptor = crate::interceptor::Interceptor::new();
    for _ in 0..150 {
        if module_present("HoYoChannel.dll") {
            crate::plog!("late scan: HoYoChannel.dll present");
            scan_extra(&mut interceptor, "HoYoChannel.dll");
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    std::mem::forget(interceptor);
}

/// HYPass.dll config reader (RVA 0x12FD90, found by reversing the rsa_key
/// validation path): rcx = config obj, rdx = key C-string, returns value ptr
/// in rax. Logs the rsa_key VALUE the client actually sees.
unsafe fn late_hypass_probe() {
    let mut interceptor = crate::interceptor::Interceptor::new();
    for _ in 0..150 {
        let base = module_base("HYPass.dll");
        if base != 0 {
            let addr = base.wrapping_add(0x12FD90);
            crate::plog!("hypass probe: hooking config reader at 0x{:X}", addr);
            let _ = interceptor.attach(addr, on_hypass_config_read);
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    std::mem::forget(interceptor);
}

unsafe fn module_base(name: &str) -> usize {
    let c = std::ffi::CString::new(name).unwrap();
    let pc = windows::core::PCSTR(c.as_ptr() as *const u8);
    use windows::Win32::System::LibraryLoader::GetModuleHandleA;
    match GetModuleHandleA(pc) {
        Ok(h) => h.0 as usize,
        Err(_) => 0,
    }
}

unsafe extern "win64" fn on_hypass_config_read(reg: *mut Registers, _: usize) {
    // NOTE: JmpBack fires on ENTRY. rax is not the result yet - we log the
    // key being queried. Result capture needs a return hook (phase 2).
    let key_ptr = (*reg).rdx as *const i8;
    if key_ptr.is_null() {
        return;
    }
    let key = std::ffi::CStr::from_ptr(key_ptr).to_string_lossy().into_owned();
    if key.contains("rsa_key") || key.contains("storage_encryption") || key.contains("hosts") {
        let ret = (*reg).get_stack(0);
        let (modname, base, rva) = crate::modules::tracer::resolve(ret);
        crate::plog!(
            "[hypass] config read key=\"{}\" ret=0x{:X} {}+0x{:X}",
            key,
            ret,
            modname,
            rva
        );
    }
}

impl MhyModule for MhyContext<Security> {
    unsafe fn init(&mut self) -> Result<()> {

        let mhyrsa_perform_crypto_action = util::pattern_scan_code(self.assembly_name, MHYRSA_PERFORM_CRYPTO_ACTION);
        if let Some(addr) = mhyrsa_perform_crypto_action {
            crate::plog!("mhyrsa_perform_crypto_action: {:x}", addr as usize);
            self.interceptor.attach(
                addr as usize,
                on_mhy_rsa,
            )?;
        }
        else
        {
            crate::plog!("Failed to find mhyrsa_perform_crypto_action");
        }

        let key_sign_check = util::pattern_scan_code(self.assembly_name, KEY_SIGN_CHECK);
        if let Some(addr) = key_sign_check {
            let addr_offset = addr as usize + KEY_SIGN_CHECK_OFFSET;
            crate::plog!("key_sign_check: {:x}", addr_offset as usize);
            self.interceptor.attach(
                addr_offset as usize,
                after_key_sign_check,
            )?;
        }
        else
        {
            crate::plog!("Failed to find key_sign_check");
        }


        let sdk_util_rsa_encrypt = util::pattern_scan_il2cpp(self.assembly_name, SDK_UTIL_RSA_ENCRYPT);
        if let Some(addr) = sdk_util_rsa_encrypt {
            crate::plog!("sdk_util_rsa_encrypt: {:x}", addr as usize);
            self.interceptor.attach(
                addr as usize,
                on_sdk_util_rsa_encrypt,
            )?;
        }
        else
        {
            crate::plog!("Failed to find sdk_util_rsa_encrypt");
        }

        // 7.1 moved the live SDK crypto out of YuanShen.exe (the hits above
        // are dead code - they never fire). Scan the account SDK plugin and
        // the protector with the same patterns. Missing module => skip.
        for extra in ["HoYoChannel.dll", "mhypbase.dll"] {
            scan_extra(&mut self.interceptor, extra);
        }
        // HoYoChannel loads lazily (only when login starts) - keep polling.
        std::thread::spawn(|| unsafe { late_crypto_scan() });
        // HYPass config reader probe (logs rsa_key queries).
        std::thread::spawn(|| unsafe { late_hypass_probe() });

        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Security
    }
}

unsafe extern "win64" fn after_key_sign_check(reg: *mut Registers, _: usize) {
    crate::plog!("key sign check!");
    (*reg).rax = 1
}

unsafe extern "win64" fn on_mhy_rsa(reg: *mut Registers, _: usize) {
    crate::plog!("key: {:X}", *((*reg).r12 as *const u64));
    crate::plog!("len: {:X}", (*reg).r8 -3);

    if ((*reg).r8 as usize) - 3 == KEY_SIZE {
        crate::plog!("[*] key replaced");

        std::ptr::copy_nonoverlapping(
            SERVER_PUBLIC_KEY.as_ptr(),
            (*reg).r13 as *mut u8,
            SERVER_PUBLIC_KEY.len(),
        );
    }
}

unsafe extern "win64" fn on_sdk_util_rsa_encrypt(reg: *mut Registers, _: usize) {
    // rcx = key, rdx = plaintext
    crate::plog!("[*] SDK RSA: key replaced");
    (*reg).rcx =
        marshal::ptr_to_string_ansi(CString::new(SDK_PUBLIC_KEY).unwrap().as_c_str()) as u64;
}

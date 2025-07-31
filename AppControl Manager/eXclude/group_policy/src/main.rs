use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use windows::{core::*, Win32::System::Com::*, Win32::System::Registry::HKEY};

type BOOL = i32;

const CLSID_GROUP_POLICY_OBJECT: GUID = GUID::from_u128(0xEA502722_A23D_11d1_A7D3_0000F87571E3);

const GPO_OPEN_LOAD_REGISTRY: u32 = 0x00000001;

#[repr(C)]
struct IGroupPolicyObjectVtbl {
    base: windows::core::IUnknown_Vtbl,
    new: unsafe extern "system" fn(
        this: *mut std::ffi::c_void,
        pszdomain_name: PCWSTR,
        pszdisplay_name: PCWSTR,
        dwflags: u32,
    ) -> HRESULT,
    open_ds_gpo: unsafe extern "system" fn(
        this: *mut std::ffi::c_void,
        pszpath: PCWSTR,
        dwflags: u32,
    ) -> HRESULT,
    open_local_machine_gpo:
        unsafe extern "system" fn(this: *mut std::ffi::c_void, dwflags: u32) -> HRESULT,
    open_remote_machine_gpo: unsafe extern "system" fn(
        this: *mut std::ffi::c_void,
        pszcomputer_name: PCWSTR,
        dwflags: u32,
    ) -> HRESULT,
    save: unsafe extern "system" fn(
        this: *mut std::ffi::c_void,
        bmachine: BOOL,
        badd: BOOL,
        pguidextension: *const GUID,
        pguid: *const GUID,
    ) -> HRESULT,
    delete: unsafe extern "system" fn(this: *mut std::ffi::c_void) -> HRESULT,
    get_name:
        unsafe extern "system" fn(this: *mut std::ffi::c_void, pszname: *mut PWSTR) -> HRESULT,
    get_display_name:
        unsafe extern "system" fn(this: *mut std::ffi::c_void, pszname: *mut PWSTR) -> HRESULT,
    set_display_name:
        unsafe extern "system" fn(this: *mut std::ffi::c_void, pszname: PCWSTR) -> HRESULT,
    get_path:
        unsafe extern "system" fn(this: *mut std::ffi::c_void, pszpath: *mut PWSTR) -> HRESULT,
    get_ds_path: unsafe extern "system" fn(
        this: *mut std::ffi::c_void,
        dwsection: u32,
        pszpath: *mut PWSTR,
    ) -> HRESULT,
    get_file_sys_path: unsafe extern "system" fn(
        this: *mut std::ffi::c_void,
        dwsection: u32,
        pszpath: *mut PWSTR,
    ) -> HRESULT,
    get_registry_key: unsafe extern "system" fn(
        this: *mut std::ffi::c_void,
        dwsection: u32,
        hkey: *mut HKEY,
    ) -> HRESULT,
    get_options:
        unsafe extern "system" fn(this: *mut std::ffi::c_void, dwoptions: *mut u32) -> HRESULT,
    set_options: unsafe extern "system" fn(
        this: *mut std::ffi::c_void,
        dwoptions: u32,
        dwmask: u32,
    ) -> HRESULT,
    get_type: unsafe extern "system" fn(
        this: *mut std::ffi::c_void,
        gpotype: *mut *mut std::ffi::c_void,
    ) -> HRESULT,
    get_machine_name:
        unsafe extern "system" fn(this: *mut std::ffi::c_void, pszname: *mut PWSTR) -> HRESULT,
    get_property_sheet_pages: unsafe extern "system" fn(
        this: *mut std::ffi::c_void,
        hpages: *mut *mut std::ffi::c_void,
    ) -> HRESULT,
}

#[repr(transparent)]
struct IGroupPolicyObject(windows::core::IUnknown);

impl IGroupPolicyObject {
    unsafe fn save(
        &self,
        bmachine: BOOL,
        badd: BOOL,
        pguidextension: *const GUID,
        pguid: *const GUID,
    ) -> HRESULT {
        let vtbl: *const IGroupPolicyObjectVtbl =
            unsafe { *(self.0.as_raw() as *const *const IGroupPolicyObjectVtbl) };
        unsafe { ((*vtbl).save)(self.0.as_raw(), bmachine, badd, pguidextension, pguid) }
    }

    unsafe fn open_local_machine_gpo(&self, dwflags: u32) -> HRESULT {
        let vtbl: *const IGroupPolicyObjectVtbl =
            unsafe { *(self.0.as_raw() as *const *const IGroupPolicyObjectVtbl) };
        unsafe { ((*vtbl).open_local_machine_gpo)(self.0.as_raw(), dwflags) }
    }
}

// CSE GUIDs for machine extensions
const REQUIRED_MACHINE_EXTENSIONS_IN_ORDER: [GUID; 7] = [
    GUID::from_u128(0x2A8FDC61_2347_4C87_92F6_B05EB91A201A), // Mitigation Options
    GUID::from_u128(0x35378EAC_683F_11D2_A89A_00C04FBBCFA2), // Registry
    GUID::from_u128(0x4CFB60C1_FAA6_47F1_89AA_0B18730C9FD3), // Internet Explorer Zone Mapping
    GUID::from_u128(0x827D319E_6EAC_11D2_A4EA_00C04F79F83A), // Security
    GUID::from_u128(0xD76B9641_3288_4F75_942D_087DE603E3EA), // LAPS
    GUID::from_u128(0xF312195E_3D9D_447A_A3F5_08DFFA24735E), // Device Guard Virtualization Based Security
    GUID::from_u128(0xF3CCC681_B74C_4060_9F26_CD84525DCA2A), // Audit Policy Configuration
];

// CSE GUIDs for user extensions
const REQUIRED_USER_EXTENSIONS_IN_ORDER: [GUID; 5] = [
    GUID::from_u128(0x2A8FDC61_2347_4C87_92F6_B05EB91A201A), // Mitigation Options
    GUID::from_u128(0x35378EAC_683F_11D2_A89A_00C04FBBCFA2), // Registry
    GUID::from_u128(0x4CFB60C1_FAA6_47F1_89AA_0B18730C9FD3), // Internet Explorer Zone Mapping
    GUID::from_u128(0xF312195E_3D9D_447A_A3F5_08DFFA24735E), // Device Guard Virtualization Based Security
    GUID::from_u128(0xF3CCC681_B74C_4060_9F26_CD84525DCA2A), // Audit Policy Configuration
];

const SNAPIN_GUID: GUID = GUID::from_u128(0xDF3DC19F_F72C_4030_940E_4C2A65A6B612);

/// Function to parse GUID string into GUID structure
fn parse_guid_string(guid_str: &str) -> std::result::Result<GUID, &'static str> {
    // Remove braces and hyphens, convert to uppercase
    let clean_str: String = guid_str
        .chars()
        .filter(|c: &char| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();

    if clean_str.len() != 32 {
        return Err("Invalid GUID format");
    }

    let data1: u32 = u32::from_str_radix(&clean_str[0..8], 16).map_err(|_| "Invalid GUID data1")?;
    let data2: u16 =
        u16::from_str_radix(&clean_str[8..12], 16).map_err(|_| "Invalid GUID data2")?;
    let data3: u16 =
        u16::from_str_radix(&clean_str[12..16], 16).map_err(|_| "Invalid GUID data3")?;

    let mut data4: [u8; 8] = [0; 8];
    for i in 0..8 {
        data4[i] = u8::from_str_radix(&clean_str[16 + i * 2..18 + i * 2], 16)
            .map_err(|_| "Invalid GUID data4")?;
    }

    Ok(GUID {
        data1,
        data2,
        data3,
        data4,
    })
}

fn bool_to_bool(value: bool) -> BOOL {
    if value {
        1
    } else {
        0
    }
}

/// Register predefined CSE GUIDs for both machine and user configurations
pub fn register_preset_cse_guids() -> i32 {
    unsafe {
        let init_hr: HRESULT = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let should_uninitialize: bool = if init_hr.is_ok() {
            true
        } else if init_hr.0 == 0x80010106u32 as i32 {
            // RPC_E_CHANGED_MODE - COM already initialized
            false
        } else {
            eprintln!("Failed to initialize COM. HRESULT: 0x{:08X}", init_hr.0);
            return init_hr.0;
        };

        let gpo_unknown: IUnknown =
            match CoCreateInstance(&CLSID_GROUP_POLICY_OBJECT, None, CLSCTX_INPROC_SERVER) {
                Ok(obj) => obj,
                Err(err) => {
                    eprintln!(
                        "Failed to create Group Policy Object. HRESULT: 0x{:08X}",
                        err.code().0
                    );
                    if should_uninitialize {
                        CoUninitialize();
                    }
                    return err.code().0;
                }
            };

        let gpo: IGroupPolicyObject = IGroupPolicyObject(gpo_unknown);

         let open_result: HRESULT = gpo.open_local_machine_gpo(GPO_OPEN_LOAD_REGISTRY);
        if open_result.is_err() {
            eprintln!(
                "Failed to open local machine GPO. HRESULT: 0x{:08X}",
                open_result.0
            );
            if should_uninitialize {
                CoUninitialize();
            }
            return open_result.0;
        }

        let mut overall_success: bool = true;

        // Register machine CSE GUIDs
        for extension_guid in REQUIRED_MACHINE_EXTENSIONS_IN_ORDER.iter() {
            let save_result: HRESULT = gpo.save(
                bool_to_bool(true), // bMachine: true for machine configuration
                bool_to_bool(true), // bAdd: true to add the extension
                extension_guid as *const GUID,
                &SNAPIN_GUID as *const GUID,
            );

            if save_result.is_err() {
                eprintln!(
                    "Failed to register Machine CSE GUID {{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}. HRESULT: 0x{:08X}",
                    extension_guid.data1,
                    extension_guid.data2,
                    extension_guid.data3,
                    extension_guid.data4[0],
                    extension_guid.data4[1],
                    extension_guid.data4[2],
                    extension_guid.data4[3],
                    extension_guid.data4[4],
                    extension_guid.data4[5],
                    extension_guid.data4[6],
                    extension_guid.data4[7],
                    save_result.0
                );
                overall_success = false;
            }
        }

        // Register user CSE GUIDs
        for extension_guid in REQUIRED_USER_EXTENSIONS_IN_ORDER.iter() {
            let save_result: HRESULT = gpo.save(
                bool_to_bool(false), // bMachine: false for user configuration
                bool_to_bool(true),  // bAdd: true to add the extension
                extension_guid as *const GUID,
                &SNAPIN_GUID as *const GUID,
            );

            if save_result.is_err() {
                eprintln!(
                    "Failed to register User CSE GUID {{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}. HRESULT: 0x{:08X}",
                    extension_guid.data1,
                    extension_guid.data2,
                    extension_guid.data3,
                    extension_guid.data4[0],
                    extension_guid.data4[1],
                    extension_guid.data4[2],
                    extension_guid.data4[3],
                    extension_guid.data4[4],
                    extension_guid.data4[5],
                    extension_guid.data4[6],
                    extension_guid.data4[7],
                    save_result.0
                );
                overall_success = false;
            }
        }

        if should_uninitialize {
            CoUninitialize();
        }

        if overall_success {
            0 // S_OK
        } else {
            0x80004005u32 as i32 // E_FAIL
        }
    }
}

/// Main Group Policy Save function
/// b_machine - true for machine configuration, false for user configuration
/// b_add - true to add the extension, false to remove it
/// guid_extension_str - GUID string for the extension (CSE GUID)
/// guid_str - GUID string for the snapin
/// Returns HRESULT value (0 = S_OK for success, error code for failure)
#[unsafe(no_mangle)]
pub extern "C" fn group_policy_save(
    b_machine: bool,
    b_add: bool,
    guid_extension_str: *const c_char,
    guid_str: *const c_char,
) -> i32 {
    if guid_extension_str.is_null() || guid_str.is_null() {
        return 0x80070057u32 as i32;
    }

    let extension_guid_string: String = match unsafe { CStr::from_ptr(guid_extension_str) }.to_str()
    {
        Ok(s) => s.to_string(),
        Err(_) => return 0x80070057u32 as i32,
    };

    let snapin_guid_string: String = match unsafe { CStr::from_ptr(guid_str) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return 0x80070057u32 as i32,
    };

    let extension_guid: GUID = match parse_guid_string(&extension_guid_string) {
        Ok(guid) => guid,
        Err(_) => return 0x80070057u32 as i32,
    };

    let snapin_guid: GUID = match parse_guid_string(&snapin_guid_string) {
        Ok(guid) => guid,
        Err(_) => return 0x80070057u32 as i32,
    };

    unsafe {
        let init_hr: HRESULT = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let should_uninitialize: bool = if init_hr.is_ok() {
            true
        } else if init_hr.0 == 0x80010106u32 as i32 {
            // RPC_E_CHANGED_MODE - COM already initialized
            false
        } else {
            return init_hr.0;
        };

        let gpo_unknown: IUnknown =
            match CoCreateInstance(&CLSID_GROUP_POLICY_OBJECT, None, CLSCTX_INPROC_SERVER) {
                Ok(obj) => obj,
                Err(err) => {
                    if should_uninitialize {
                        CoUninitialize();
                    }
                    return err.code().0;
                }
            };

        let gpo: IGroupPolicyObject = IGroupPolicyObject(gpo_unknown);

        // Open local machine GPO
        let open_result: HRESULT = gpo.open_local_machine_gpo(GPO_OPEN_LOAD_REGISTRY);
        if open_result.is_err() {
            if should_uninitialize {
                CoUninitialize();
            }
            return open_result.0;
        }

        let save_result: HRESULT = gpo.save(
            bool_to_bool(b_machine),
            bool_to_bool(b_add),
            &extension_guid as *const GUID,
            &snapin_guid as *const GUID,
        );

        if should_uninitialize {
            CoUninitialize();
        }

        save_result.0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn free_c_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Check for -Preset parameter
    if args.len() == 2 && args[1].eq_ignore_ascii_case("-preset") {
        let result: i32 = register_preset_cse_guids();
        std::process::exit(if result == 0 { 0 } else { 1 });
    }

    if args.len() != 5 {
        eprintln!("Invalid arguments. Expected either '-Preset' or '<b_machine> <b_add> <extension_guid> <snapin_guid>'");
        std::process::exit(1);
    }

    // Parse command line arguments
    let b_machine: bool = match args[1].to_lowercase().as_str() {
        "true" => true,
        "false" => false,
        _ => {
            eprintln!("Error: b_machine must be 'true' or 'false'");
            std::process::exit(1);
        }
    };

    let b_add: bool = match args[2].to_lowercase().as_str() {
        "true" => true,
        "false" => false,
        _ => {
            eprintln!("Error: b_add must be 'true' or 'false'");
            std::process::exit(1);
        }
    };

    let extension_guid_str: &str = &args[3];
    let snapin_guid_str: &str = &args[4];

    let extension_guid: CString = match CString::new(extension_guid_str) {
        Ok(cstr) => cstr,
        Err(_) => {
            eprintln!("Error: Invalid extension GUID string");
            std::process::exit(1);
        }
    };

    let snapin_guid: CString = match CString::new(snapin_guid_str) {
        Ok(cstr) => cstr,
        Err(_) => {
            eprintln!("Error: Invalid snapin GUID string");
            std::process::exit(1);
        }
    };

    let result: i32 = group_policy_save(
        b_machine,
        b_add,
        extension_guid.as_ptr(),
        snapin_guid.as_ptr(),
    );

    if result != 0 {
        eprintln!("Failed to register CSE GUID. HRESULT: 0x{:08X}", result);
        std::process::exit(1);
    }

    std::process::exit(0);
}

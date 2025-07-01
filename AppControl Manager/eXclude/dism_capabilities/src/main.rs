use std::ffi::{OsString, c_void};
use std::os::windows::ffi::{OsStringExt, OsStrExt};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_SUCCESS, HMODULE, FreeLibrary};
use windows::Win32::System::LibraryLoader::{LoadLibraryW, GetProcAddress};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DismSession(u32);

#[repr(C)]
#[derive(Debug)]
#[allow(dead_code)]
enum DismLogLevel {
    DismLogErrors = 0,
    DismLogErrorsWarnings = 1,
    DismLogErrorsWarningsInfo = 2,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum DismPackageFeatureState {
    DismStateNotPresent = 0,
    DismStateUninstallPending = 1,
    DismStateStaged = 2,
    DismStateRemoved = 3,
    DismStateInstalled = 4,
    DismStateInstallPending = 5,
    DismStateSuperseded = 6,
    DismStatePartiallyInstalled = 7,
}

// Using packed to match C (12 bytes: 8+4) instead of Rust's default (16 bytes: 8+4+4 padding)
#[repr(C, packed)]
#[derive(Debug)]
struct DismCapability {
    name: *const u16,               // PCWSTR (pointer)
    state: DismPackageFeatureState, // DismPackageFeatureState (u32)
}

// DISM_REMOVECAPABILITY struct (32 bytes, reserved)
#[repr(C)]
#[derive(Debug, Default)]
struct DismRemoveCapability {
    reserved: [u8; 32],
}

type DismProgressCallback = Option<unsafe extern "system" fn(current: u32, total: u32, user_data: *mut c_void)>;

// Function pointer types for capability enable/disable with progress
type DismAddCapabilityFn = unsafe extern "system" fn(
    DismSession,
    PCWSTR,                   // capability name
    bool,                     // limit access
    *const PCWSTR,            // source paths (PCWSTR* array)
    u32,                      // source path count
    *mut c_void,              // cancel event
    DismProgressCallback,     // progress callback
    *mut c_void,              // user data
) -> u32;

type DismRemoveCapabilityFn = unsafe extern "system" fn(
    DismSession,
    PCWSTR,                   // capability name
    *mut c_void,              // cancel event
    DismProgressCallback,     // progress callback
    *mut c_void,              // user data
) -> u32;

type DismInitializeFn = unsafe extern "system" fn(DismLogLevel, PCWSTR, PCWSTR) -> u32;
type DismShutdownFn = unsafe extern "system" fn() -> u32;
type DismOpenSessionFn = unsafe extern "system" fn(PCWSTR, PCWSTR, PCWSTR, *mut DismSession) -> u32;
type DismCloseSessionFn = unsafe extern "system" fn(DismSession) -> u32;
type DismGetCapabilitiesFn = unsafe extern "system" fn(DismSession, *mut *mut DismCapability, *mut u32) -> u32;
type DismDeleteFn = unsafe extern "system" fn(*mut c_void) -> u32;

struct DismApi {
    module: HMODULE,
    initialize: DismInitializeFn,
    shutdown: DismShutdownFn,
    open_session: DismOpenSessionFn,
    close_session: DismCloseSessionFn,
    get_capabilities: DismGetCapabilitiesFn,
    delete: DismDeleteFn,
    add_capability: Option<DismAddCapabilityFn>,
    remove_capability: Option<DismRemoveCapabilityFn>,
}

impl DismApi {
    fn load() -> std::result::Result<Self, String> {
        unsafe {
            let dll_name = windows::core::w!("DismApi.dll");
            let module = LoadLibraryW(dll_name);

            match module {
                Ok(mod_handle) => {
                    if mod_handle.is_invalid() {
                        return Err("Failed to load DismApi.dll".to_string());
                    }

                    let initialize_name = windows::core::s!("DismInitialize");
                    let shutdown_name = windows::core::s!("DismShutdown");
                    let open_session_name = windows::core::s!("DismOpenSession");
                    let close_session_name = windows::core::s!("DismCloseSession");
                    let get_capabilities_name = windows::core::s!("DismGetCapabilities");
                    let delete_name = windows::core::s!("DismDelete");
                    let add_capability_name = windows::core::s!("DismAddCapability");
                    let remove_capability_name = windows::core::s!("DismRemoveCapability");

                    let initialize = GetProcAddress(mod_handle, initialize_name);
                    let shutdown = GetProcAddress(mod_handle, shutdown_name);
                    let open_session = GetProcAddress(mod_handle, open_session_name);
                    let close_session = GetProcAddress(mod_handle, close_session_name);
                    let get_capabilities = GetProcAddress(mod_handle, get_capabilities_name);
                    let delete = GetProcAddress(mod_handle, delete_name);
                    let add_capability = GetProcAddress(mod_handle, add_capability_name);
                    let remove_capability = GetProcAddress(mod_handle, remove_capability_name);

                    if initialize.is_none() || shutdown.is_none() || open_session.is_none() ||
                        close_session.is_none() || get_capabilities.is_none() || delete.is_none() {
                        let _ = FreeLibrary(mod_handle);
                        return Err("Failed to get DISM API function addresses".to_string());
                    }

                    Ok(DismApi {
                        module: mod_handle,
                        initialize: std::mem::transmute(initialize.unwrap()),
                        shutdown: std::mem::transmute(shutdown.unwrap()),
                        open_session: std::mem::transmute(open_session.unwrap()),
                        close_session: std::mem::transmute(close_session.unwrap()),
                        get_capabilities: std::mem::transmute(get_capabilities.unwrap()),
                        delete: std::mem::transmute(delete.unwrap()),
                        add_capability: add_capability.map(|f| std::mem::transmute(f)),
                        remove_capability: remove_capability.map(|f| std::mem::transmute(f)),
                    })
                }
                Err(_) => Err("Failed to load DismApi.dll".to_string()),
            }
        }
    }

    /// Enables (installs) a capability by name, with progress reporting.
    fn enable_capability_with_progress(
        &self,
        session: DismSession,
        capability_name: &str,
        limit_access: bool,
        source_paths: Option<&[&str]>,
    ) -> std::result::Result<(), String> {
        let add_fn = self.add_capability.ok_or("DismAddCapability not loaded")?;
        // Convert capability name to wide string and NUL-terminate
        let wide_name: Vec<u16> = std::ffi::OsStr::new(capability_name).encode_wide().chain([0]).collect();

        // Handle source paths (array of PCWSTR)
        let (source_paths_ptr, source_path_count, string_ptrs): ( *const PCWSTR, u32, Vec<Vec<u16>> ) = if let Some(paths) = source_paths {
            let mut strings: Vec<Vec<u16>> = paths.iter().map(|&p| std::ffi::OsStr::new(p).encode_wide().chain([0]).collect()).collect();
            let ptrs: Vec<PCWSTR> = strings.iter().map(|s| PCWSTR(s.as_ptr())).collect();
            (ptrs.as_ptr(), ptrs.len() as u32, strings)
        } else {
            (ptr::null(), 0, Vec::new())
        };

        // Progress state shared between callback and main
        let progress_printed = Arc::new(AtomicBool::new(false));

        unsafe extern "system" fn progress_callback(current: u32, total: u32, user_data: *mut c_void) {
            if total > 0 {
                let percentage = (current as f64 * 100.0) / total as f64;
                println!("Progress: {}/{} ({:.2}%)", current, total, percentage);
            } else {
                println!("Progress: {}/unknown", current);
            }
            if !user_data.is_null() {
                let atomic_bool = &*(user_data as *const AtomicBool);
                atomic_bool.store(true, Ordering::SeqCst);
            }
        }

        println!("Attempting to add capability: {capability_name}");

        // Use user_data to pass Arc::AtomicBool for at least one callback
        let user_data = Arc::into_raw(progress_printed.clone()) as *mut c_void;

        let hr = unsafe {
            add_fn(
                session,
                PCWSTR(wide_name.as_ptr()),
                limit_access,
                source_paths_ptr,
                source_path_count,
                ptr::null_mut(), // CancelEvent
                Some(progress_callback),
                user_data,
            )
        };

        // Drop the Arc reference (does not free if callback took a ref)
        unsafe { let _ = Arc::from_raw(user_data as *const AtomicBool); }

        if hr == ERROR_SUCCESS.0 {
            println!("Successfully added capability: {capability_name}");
            Ok(())
        } else {
            println!("Failed to add capability: {capability_name}. Error code: {hr:#X}");
            Err(format!("Failed to enable capability '{}'. Error code: {:#X}", capability_name, hr))
        }
    }

    /// Disables (removes) a capability by name, with progress reporting.
    fn disable_capability_with_progress(
        &self,
        session: DismSession,
        capability_name: &str,
    ) -> std::result::Result<(), String> {
        let remove_fn = self.remove_capability.ok_or("DismRemoveCapability not loaded")?;
        // Convert to wide string and NUL-terminate
        let wide: Vec<u16> = std::ffi::OsStr::new(capability_name).encode_wide().chain([0]).collect();

        // Progress state shared between callback and main
        let progress_printed = Arc::new(AtomicBool::new(false));

        unsafe extern "system" fn progress_callback(current: u32, total: u32, user_data: *mut c_void) {
            if total > 0 {
                let percentage = (current as f64 * 100.0) / total as f64;
                println!("Progress: {}/{} ({:.2}%)", current, total, percentage);
            } else {
                println!("Progress: {}/unknown", current);
            }
            if !user_data.is_null() {
                let atomic_bool = &*(user_data as *const AtomicBool);
                atomic_bool.store(true, Ordering::SeqCst);
            }
        }

        println!("Attempting to remove capability: {capability_name}");

        // Use user_data to pass Arc::AtomicBool for at least one callback
        let user_data = Arc::into_raw(progress_printed.clone()) as *mut c_void;

        let hr = unsafe {
            remove_fn(
                session,
                PCWSTR(wide.as_ptr()),
                ptr::null_mut(), // CancelEvent
                Some(progress_callback),
                user_data,
            )
        };

        // Drop the Arc reference (does not free if callback took a ref)
        unsafe { let _ = Arc::from_raw(user_data as *const AtomicBool); }

        if hr == ERROR_SUCCESS.0 {
            println!("Successfully removed capability: {capability_name}");
            Ok(())
        } else {
            println!("Failed to remove capability: {capability_name}. Error code: {hr:#X}");
            Err(format!("Failed to disable capability '{}'. Error code: {:#X}", capability_name, hr))
        }
    }
}

impl Drop for DismApi {
    fn drop(&mut self) {
        unsafe {
            if !self.module.is_invalid() {
                let _ = FreeLibrary(self.module);
            }
        }
    }
}

// RAII guard to ensure DISM is properly shut down
struct DismGuard<'a> {
    api: &'a DismApi,
}

impl<'a> DismGuard<'a> {
    fn new(api: &'a DismApi) -> Self {
        DismGuard { api }
    }
}

impl Drop for DismGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            (self.api.shutdown)();
        }
    }
}

// RAII guard to ensure DISM session is properly closed
struct SessionGuard<'a> {
    api: &'a DismApi,
    session: DismSession,
}

impl<'a> SessionGuard<'a> {
    fn new(api: &'a DismApi, session: DismSession) -> Self {
        SessionGuard { api, session }
    }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            (self.api.close_session)(self.session);
        }
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("Loading DISM API...");

    // Load DISM API
    let dism_api = DismApi::load()
        .map_err(|e| e)?;

    println!("Initializing DISM API...");

    // Initialize DISM
    unsafe {
        let result = (dism_api.initialize)(
            DismLogLevel::DismLogErrorsWarnings,
            PCWSTR(ptr::null()),
            PCWSTR(ptr::null())
        );
        if result != ERROR_SUCCESS.0 {
            return Err(format!("Failed to initialize DISM API. Error code: {}", result).into());
        }
    }

    // Ensure DISM is properly shut down when we're done
    let _guard = DismGuard::new(&dism_api);

    println!("Opening DISM session...");

    // For online image, use the constant from the header
    let online_image = windows::core::w!("DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}");

    // Open session for online image
    let mut session = DismSession(0);
    unsafe {
        let result = (dism_api.open_session)(
            online_image,
            PCWSTR(ptr::null()),
            PCWSTR(ptr::null()),
            &mut session,
        );
        if result != ERROR_SUCCESS.0 {
            return Err(format!("Failed to open DISM session. Error code: {}. Need Admin!!!.", result).into());
        }
    }

    // Ensure session is properly closed when we're done
    let _session_guard = SessionGuard::new(&dism_api, session);

    println!("Retrieving Windows capabilities...\n");

    let mut capabilities: *mut DismCapability = ptr::null_mut();
    let mut capability_count: u32 = 0;

    unsafe {
        let result = (dism_api.get_capabilities)(
            session,
            &mut capabilities,
            &mut capability_count,
        );

        if result != ERROR_SUCCESS.0 {
            return Err(format!("Failed to get capabilities. Error code: {}", result).into());
        }

        if capabilities.is_null() || capability_count == 0 || capability_count > 10_000 {
            println!("No capabilities found or suspiciously large number reported. Aborting.");
            return Ok(());
        }

        println!("Found {} Windows capabilities:\n", capability_count);
        println!("{:<80} {:<15}", "Capability Name", "State");
        println!("{}", "=".repeat(95));

        let mut state_counts = std::collections::HashMap::new();
        let mut processed_count = 0;

        // Create a slice from the pointer for safer access
        let capabilities_slice = std::slice::from_raw_parts(capabilities, capability_count as usize);

        for capability in capabilities_slice.iter() {
            let name_ptr_value = capability.name as usize;
            let name = if capability.name.is_null()
                || name_ptr_value < 0x1000
                || name_ptr_value > 0x7FFFFFFFFFFF
                || name_ptr_value % std::mem::align_of::<u16>() != 0
            {
                String::from("<invalid>")
            } else {
                // Use catch_unwind to avoid panics from FFI memory errors
                std::panic::catch_unwind(|| {
                    let mut len = 0;
                    let mut cur = capability.name;
                    while len < 2048 {
                        let c = ptr::read(cur);
                        if c == 0 { break; }
                        if c < 32 && c != 0 { return String::from("<invalid_char>"); }
                        len += 1;
                        cur = cur.add(1);
                    }
                    if len == 0 { return String::from("<empty>"); }
                    let slice = std::slice::from_raw_parts(capability.name, len);
                    OsString::from_wide(slice).to_string_lossy().into_owned()
                }).unwrap_or_else(|_| String::from("<panic>"))
            };

            // skip weird invalid names
            if name == "<invalid>" || name == "<invalid_char>" || name == "<empty>" || name == "<panic>" {
                continue;
            }

            let state_str = match capability.state {
                DismPackageFeatureState::DismStateNotPresent => "NotPresent",
                DismPackageFeatureState::DismStateUninstallPending => "UninstallPending",
                DismPackageFeatureState::DismStateStaged => "Staged",
                DismPackageFeatureState::DismStateRemoved => "Removed",
                DismPackageFeatureState::DismStateInstalled => "Installed",
                DismPackageFeatureState::DismStateInstallPending => "InstallPending",
                DismPackageFeatureState::DismStateSuperseded => "Superseded",
                DismPackageFeatureState::DismStatePartiallyInstalled => "PartiallyInstalled",
            };

            println!("{:<80} {:<15}",
                &name.to_string(),
                state_str
            );

            *state_counts.entry(state_str.to_string()).or_insert(0) += 1;
            processed_count += 1;

            if processed_count % 20 == 0 {
                println!();
            }
        }

        println!("\n{}", "=".repeat(95));
        println!("Successfully processed {} capabilities out of {} total.", processed_count, capability_count);

        println!("\nCapabilities by state:");
        let mut sorted_states: Vec<_> = state_counts.into_iter().collect();
        sorted_states.sort_by(|a, b| b.1.cmp(&a.1));

        for (state, count) in sorted_states {
            println!("  {}: {}", state, count);
        }

       // let capability_to_remove = "XPS.Viewer~~~~0.0.1.0";
       // let _ = dism_api.disable_capability_with_progress(session, capability_to_remove);

        //let capability_to_add = "XPS.Viewer~~~~0.0.1.0";
        // let _ = dism_api.enable_capability_with_progress(session, capability_to_add, false, None);

        // Free the capabilities array memory
        let _ = (dism_api.delete)(capabilities as *mut c_void);
    }

    println!("\nCapability listing completed successfully.");
    Ok(())
}

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use windows::{
    core::*,
    Win32::System::Com::*,
    Win32::UI::Shell::*,
    Win32::UI::Shell::Common::COMDLG_FILTERSPEC,
    Win32::Foundation::HWND,
};

// CLSID for TaskbarList COM object
const CLSID_TASKBARLIST: GUID = GUID::from_u128(0x56FDF344_FD6D_11d0_958A_006097C9A090);

// Structure to return multiple paths
#[repr(C)]
pub struct StringArray {
    pub strings: *mut *mut c_char,
    pub count: i32,
}

// To convert Rust String to C string
fn string_to_c_char(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

// To create StringArray for multiple results
fn create_string_array(paths: Vec<String>) -> StringArray {
    if paths.is_empty() {
        return StringArray {
            strings: ptr::null_mut(),
            count: 0,
        };
    }

    let count = paths.len() as i32;
    let mut c_strings: Vec<*mut c_char> = paths.into_iter()
        .map(string_to_c_char)
        .collect();

    // Allocate memory for the array of string pointers
    let strings_ptr = c_strings.as_mut_ptr();
    std::mem::forget(c_strings); // Prevent deallocation

    StringArray {
        strings: strings_ptr,
        count,
    }
}

// To parse filter string and create COMDLG_FILTERSPEC array
// Returns the filter specs plus two Vecs owning the wide-string buffers so they stay alive
fn parse_filter_string(
    filter_str: &str,
) -> (Vec<COMDLG_FILTERSPEC>, Vec<Box<[u16]>>, Vec<Box<[u16]>>) {
    if filter_str.is_empty() {
        return (Vec::new(), Vec::new(), Vec::new());
    }

    let mut specs = Vec::new();
    let mut name_bufs: Vec<Box<[u16]>> = Vec::new();
    let mut spec_bufs: Vec<Box<[u16]>> = Vec::new();

    // Split to get pairs of description and pattern
    let parts: Vec<&str> = filter_str.split('|').collect();

    // Process pairs (description, pattern)
    for chunk in parts.chunks(2) {
        if chunk.len() == 2 {
            let description = chunk[0];
            let pattern = chunk[1];

            // Convert to wide strings (UTF-16) with terminating NUL
            let desc_wide = description
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>();
            let pattern_wide = pattern
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>();

            // Move into boxed slices so they own their memory
            let desc_box = desc_wide.into_boxed_slice();
            let pattern_box = pattern_wide.into_boxed_slice();

            // Get raw pointers for COMDLG_FILTERSPEC
            let desc_ptr = desc_box.as_ptr();
            let pattern_ptr = pattern_box.as_ptr();

            // Store the boxes so they live until after the dialog call returns
            name_bufs.push(desc_box);
            spec_bufs.push(pattern_box);

            specs.push(COMDLG_FILTERSPEC {
                pszName: PCWSTR(desc_ptr),
                pszSpec: PCWSTR(pattern_ptr),
            });
        }
    }

    (specs, name_bufs, spec_bufs)
}

// To set initial directory
fn set_initial_directory(dialog: &IFileOpenDialog, initial_dir: &str) -> Result<()> {
    if initial_dir.is_empty() {
        return Ok(());
    }

    unsafe {
        // Convert path to wide string
        let wide_path: Vec<u16> = initial_dir
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Create shell item from path
        if let Ok(shell_item) = SHCreateItemFromParsingName::<PCWSTR, Option<&IBindCtx>, IShellItem>(
            PCWSTR(wide_path.as_ptr()),
            None,
        ) {
            let _ = dialog.SetFolder(&shell_item);
        }
    }

    Ok(())
}

// To check if an HRESULT indicates user cancellation
fn is_user_cancelled(hresult: i32) -> bool {
    match hresult {
        // HRESULT_FROM_WIN32(ERROR_CANCELLED) = 0x800704C7
        x if x == 0x800704C7u32 as i32 => true, // This is what's actually thrown on the C# side.
        // E_ABORT = 0x80004004
        // x if x == 0x80004004u32 as i32 => true,
        // HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) = 0x800703E3
        // x if x == 0x800703E3u32 as i32 => true,
        _ => false,
    }
}

// Internal function to show single file picker
fn show_file_picker_internal(filter: &str, initial_dir: &str, last_error: &mut i32) -> Result<String> {
    unsafe {
        let init_hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if init_hr.is_err() {
            *last_error = init_hr.0;
            return Err(Error::from(init_hr));
        }

        let file_dialog: IFileOpenDialog = match CoCreateInstance(
            &FileOpenDialog,
            None,
            CLSCTX_INPROC_SERVER,
        ) {
            Ok(dialog) => dialog,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        if let Err(err) = file_dialog.SetTitle(w!("Select a File")) {
            *last_error = err.code().0;
            CoUninitialize();
            return Err(err);
        }

        // Set initial directory
        if let Err(err) = set_initial_directory(&file_dialog, initial_dir) {
            *last_error = err.code().0;
            CoUninitialize();
            return Err(err);
        }

        // Apply filter and keep buffers alive until after Show()
        let (filters, _name_bufs, _pattern_bufs) = parse_filter_string(filter);
        if !filters.is_empty() {
            if let Err(err) = file_dialog.SetFileTypes(&filters) {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
            if let Err(err) = file_dialog.SetFileTypeIndex(1) {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        }

        let show_result = file_dialog.Show(None);
        if let Err(err) = show_result {
            let hresult = err.code().0;
            *last_error = hresult;
            CoUninitialize();

            // If user cancelled, don't treat it as an error
            if is_user_cancelled(hresult) {
                return Ok(String::new()); // Return empty string to indicate cancellation
            }

            return Err(err);
        }

        let shell_item = match file_dialog.GetResult() {
            Ok(item) => item,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        let path_pwstr = match shell_item.GetDisplayName(SIGDN_FILESYSPATH) {
            Ok(pwstr) => pwstr,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        let path = match path_pwstr.to_string() {
            Ok(s) => s,
            Err(_) => {
                // FromUtf16Error doesn't have a code() method, use a generic error code
                *last_error = 0x80070057u32 as i32; // E_INVALIDARG
                CoTaskMemFree(Some(path_pwstr.0 as *mut _));
                CoUninitialize();
                return Err(Error::from_win32());
            }
        };

        CoTaskMemFree(Some(path_pwstr.0 as *mut _));
        CoUninitialize();

        Ok(path)
    }
}

// Internal function to show multiple files picker
fn show_files_picker_internal(filter: &str, initial_dir: &str, last_error: &mut i32) -> Result<Vec<String>> {
    unsafe {
        let init_hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if init_hr.is_err() {
            *last_error = init_hr.0;
            return Err(Error::from(init_hr));
        }

        let file_dialog: IFileOpenDialog = match CoCreateInstance(
            &FileOpenDialog,
            None,
            CLSCTX_INPROC_SERVER,
        ) {
            Ok(dialog) => dialog,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        if let Err(err) = file_dialog.SetTitle(w!("Select Multiple Files")) {
            *last_error = err.code().0;
            CoUninitialize();
            return Err(err);
        }

        // Set initial directory
        if let Err(err) = set_initial_directory(&file_dialog, initial_dir) {
            *last_error = err.code().0;
            CoUninitialize();
            return Err(err);
        }

        // Set options to allow multiple selection
        let options: FILEOPENDIALOGOPTIONS = match file_dialog.GetOptions() {
            Ok(opts) => opts,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        if let Err(err) = file_dialog.SetOptions(options | FOS_ALLOWMULTISELECT) {
            *last_error = err.code().0;
            CoUninitialize();
            return Err(err);
        }

        // Apply filter and keep buffers alive until after Show()
        let (filters, _name_bufs, _pattern_bufs) = parse_filter_string(filter);
        if !filters.is_empty() {
            if let Err(err) = file_dialog.SetFileTypes(&filters) {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
            if let Err(err) = file_dialog.SetFileTypeIndex(1) {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        }

        let show_result = file_dialog.Show(None);
        if let Err(err) = show_result {
            let hresult = err.code().0;
            *last_error = hresult;
            CoUninitialize();

            // If user cancelled, don't treat it as an error
            if is_user_cancelled(hresult) {
                return Ok(Vec::new()); // Return empty vector to indicate cancellation
            }

            return Err(err);
        }

        let shell_item_array: IShellItemArray = match file_dialog.GetResults() {
            Ok(array) => array,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        let count: u32 = match shell_item_array.GetCount() {
            Ok(c) => c,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        let mut paths: Vec<String> = Vec::new();

        for i in 0..count {
            let shell_item: IShellItem = match shell_item_array.GetItemAt(i) {
                Ok(item) => item,
                Err(err) => {
                    *last_error = err.code().0;
                    CoUninitialize();
                    return Err(err);
                }
            };

            let path_pwstr: PWSTR = match shell_item.GetDisplayName(SIGDN_FILESYSPATH) {
                Ok(pwstr) => pwstr,
                Err(err) => {
                    *last_error = err.code().0;
                    CoUninitialize();
                    return Err(err);
                }
            };

            let path: String = match path_pwstr.to_string() {
                Ok(s) => s,
                Err(_) => {
                    // FromUtf16Error doesn't have a code() method, use a generic error code
                    *last_error = 0x80070057u32 as i32; // E_INVALIDARG
                    CoTaskMemFree(Some(path_pwstr.0 as *mut _));
                    CoUninitialize();
                    return Err(Error::from_win32());
                }
            };

            paths.push(path);
            CoTaskMemFree(Some(path_pwstr.0 as *mut _));
        }

        CoUninitialize();

        Ok(paths)
    }
}

// Internal function to show single folder picker
fn show_folder_picker_internal(initial_dir: &str, last_error: &mut i32) -> Result<String> {
    unsafe {
        let init_hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if init_hr.is_err() {
            *last_error = init_hr.0;
            return Err(Error::from(init_hr));
        }

        let file_dialog: IFileOpenDialog = match CoCreateInstance(
            &FileOpenDialog,
            None,
            CLSCTX_INPROC_SERVER,
        ) {
            Ok(dialog) => dialog,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        if let Err(err) = file_dialog.SetTitle(w!("Select a Folder")) {
            *last_error = err.code().0;
            CoUninitialize();
            return Err(err);
        }

        // Set initial directory
        if let Err(err) = set_initial_directory(&file_dialog, initial_dir) {
            *last_error = err.code().0;
            CoUninitialize();
            return Err(err);
        }

        // Set options to pick folders
        let options: FILEOPENDIALOGOPTIONS = match file_dialog.GetOptions() {
            Ok(opts) => opts,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        if let Err(err) = file_dialog.SetOptions(options | FOS_PICKFOLDERS) {
            *last_error = err.code().0;
            CoUninitialize();
            return Err(err);
        }

        let show_result = file_dialog.Show(None);
        if let Err(err) = show_result {
            let hresult = err.code().0;
            *last_error = hresult;
            CoUninitialize();

            // If user cancelled, don't treat it as an error
            if is_user_cancelled(hresult) {
                return Ok(String::new()); // Return empty string to indicate cancellation
            }

            return Err(err);
        }

        let shell_item: IShellItem = match file_dialog.GetResult() {
            Ok(item) => item,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        let path_pwstr: PWSTR = match shell_item.GetDisplayName(SIGDN_FILESYSPATH) {
            Ok(pwstr) => pwstr,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        let path: String = match path_pwstr.to_string() {
            Ok(s) => s,
            Err(_) => {
                // FromUtf16Error doesn't have a code() method, use a generic error code
                *last_error = 0x80070057u32 as i32; // E_INVALIDARG
                CoTaskMemFree(Some(path_pwstr.0 as *mut _));
                CoUninitialize();
                return Err(Error::from_win32());
            }
        };

        CoTaskMemFree(Some(path_pwstr.0 as *mut _));
        CoUninitialize();

        Ok(path)
    }
}

// Internal function to show multiple folders picker
fn show_folders_picker_internal(initial_dir: &str, last_error: &mut i32) -> Result<Vec<String>> {
    unsafe {
        let init_hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if init_hr.is_err() {
            *last_error = init_hr.0;
            return Err(Error::from(init_hr));
        }

        let file_dialog: IFileOpenDialog = match CoCreateInstance(
            &FileOpenDialog,
            None,
            CLSCTX_INPROC_SERVER,
        ) {
            Ok(dialog) => dialog,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        if let Err(err) = file_dialog.SetTitle(w!("Select Multiple Folders")) {
            *last_error = err.code().0;
            CoUninitialize();
            return Err(err);
        }

        // Set initial directory
        if let Err(err) = set_initial_directory(&file_dialog, initial_dir) {
            *last_error = err.code().0;
            CoUninitialize();
            return Err(err);
        }

        // Set options to pick folders and allow multiple selection
        let options: FILEOPENDIALOGOPTIONS = match file_dialog.GetOptions() {
            Ok(opts) => opts,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        if let Err(err) = file_dialog.SetOptions(options | FOS_PICKFOLDERS | FOS_ALLOWMULTISELECT) {
            *last_error = err.code().0;
            CoUninitialize();
            return Err(err);
        }

        let show_result = file_dialog.Show(None);
        if let Err(err) = show_result {
            let hresult = err.code().0;
            *last_error = hresult;
            CoUninitialize();

            // If user cancelled, don't treat it as an error
            if is_user_cancelled(hresult) {
                return Ok(Vec::new()); // Return empty vector to indicate cancellation
            }

            return Err(err);
        }

        let shell_item_array: IShellItemArray = match file_dialog.GetResults() {
            Ok(array) => array,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        let count: u32 = match shell_item_array.GetCount() {
            Ok(c) => c,
            Err(err) => {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
        };

        let mut paths: Vec<String> = Vec::new();

        for i in 0..count {
            let shell_item: IShellItem = match shell_item_array.GetItemAt(i) {
                Ok(item) => item,
                Err(err) => {
                    *last_error = err.code().0;
                    CoUninitialize();
                    return Err(err);
                }
            };

            let path_pwstr: PWSTR = match shell_item.GetDisplayName(SIGDN_FILESYSPATH) {
                Ok(pwstr) => pwstr,
                Err(err) => {
                    *last_error = err.code().0;
                    CoUninitialize();
                    return Err(err);
                }
            };

            let path: String = match path_pwstr.to_string() {
                Ok(s) => s,
                Err(_) => {
                    // FromUtf16Error doesn't have a code() method, use a generic error code
                    *last_error = 0x80070057u32 as i32; // E_INVALIDARG
                    CoTaskMemFree(Some(path_pwstr.0 as *mut _));
                    CoUninitialize();
                    return Err(Error::from_win32());
                }
            };

            paths.push(path);
            CoTaskMemFree(Some(path_pwstr.0 as *mut _));
        }

        CoUninitialize();

        Ok(paths)
    }
}

// To convert C string to Rust string
unsafe fn c_char_to_string(c_str: *const c_char) -> Option<String> {
    if c_str.is_null() {
        return None;
    }
    unsafe {
        match std::ffi::CStr::from_ptr(c_str).to_str() {
            Ok(s) => Some(s.to_string()),
            Err(_) => None,
        }
    }
}

// Internal function to update taskbar progress
fn update_taskbar_progress_internal(hwnd: isize, completed: u64, total: u64, last_error: &mut i32) -> Result<()> {
    unsafe {
        // Try to initialize COM, but don't fail if it's already initialized
        let init_hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);

        // Check if initialization succeeded or if COM was already initialized
        let should_uninitialize = if init_hr.is_ok() {
            // COM was successfully initialized by us
            true
        } else {
            // Check if it's the "already initialized" error (RPC_E_CHANGED_MODE)
            if init_hr.0 == 0x80010106u32 as i32 {
                // COM is already initialized in a different mode, continue without uninitializing
                false
            } else {
                // Some other COM initialization error
                *last_error = init_hr.0;
                return Err(Error::from(init_hr));
            }
        };

        // Create TaskbarList COM object
        let taskbar_list: ITaskbarList3 = match CoCreateInstance(
            &CLSID_TASKBARLIST,
            None,
            CLSCTX_INPROC_SERVER,
        ) {
            Ok(taskbar) => taskbar,
            Err(err) => {
                *last_error = err.code().0;
                if should_uninitialize {
                    CoUninitialize();
                }
                return Err(err);
            }
        };

        // Initialize the taskbar list
        if let Err(err) = taskbar_list.HrInit() {
            *last_error = err.code().0;
            if should_uninitialize {
                CoUninitialize();
            }
            return Err(err);
        }

        // Set the progress value
        let hwnd_handle = HWND(hwnd as *mut std::ffi::c_void);
        if let Err(err) = taskbar_list.SetProgressValue(hwnd_handle, completed, total) {
            *last_error = err.code().0;
            if should_uninitialize {
                CoUninitialize();
            }
            return Err(err);
        }

        if should_uninitialize {
            CoUninitialize();
        }
        Ok(())
    }
}

// C-compatible exports

/// Shows a single file picker dialog with filter and initial directory
/// filter: C string with filter format "Description|*.ext|Description2|*.ext2"
/// initial_dir: C string with initial directory path (can be empty)
/// last_error: Out parameter to receive the last HRESULT on error
/// Returns: pointer to C string with selected file path, or null on error/cancel
/// Caller must free the returned string using free_string()
#[unsafe(no_mangle)]
pub extern "C" fn show_file_picker(filter: *const c_char, initial_dir: *const c_char, last_error: *mut i32) -> *mut c_char {
    let filter_str = unsafe { c_char_to_string(filter) }.unwrap_or_default();
    let initial_dir_str = unsafe { c_char_to_string(initial_dir) }.unwrap_or_default();
    let mut error_code = 0i32;

    let result = match show_file_picker_internal(&filter_str, &initial_dir_str, &mut error_code) {
        Ok(path) => {
            if path.is_empty() {
                // User cancelled - don't set error code for cancellation
                ptr::null_mut()
            } else {
                string_to_c_char(path)
            }
        },
        Err(_) => {
            if !last_error.is_null() {
                unsafe { *last_error = error_code; }
            }
            ptr::null_mut()
        }
    };

    result
}

/// Shows a multiple files picker dialog with filter and initial directory
/// filter: C string with filter format "Description|*.ext|Description2|*.ext2"
/// initial_dir: C string with initial directory path (can be empty)
/// last_error: Out parameter to receive the last HRESULT on error
/// Returns: StringArray structure with selected file paths
/// Caller must free the returned array using free_string_array()
#[unsafe(no_mangle)]
pub extern "C" fn show_files_picker(filter: *const c_char, initial_dir: *const c_char, last_error: *mut i32) -> StringArray {
    let filter_str = unsafe { c_char_to_string(filter) }.unwrap_or_default();
    let initial_dir_str = unsafe { c_char_to_string(initial_dir) }.unwrap_or_default();
    let mut error_code = 0i32;

    match show_files_picker_internal(&filter_str, &initial_dir_str, &mut error_code) {
        Ok(paths) => create_string_array(paths),
        Err(_) => {
            if !last_error.is_null() {
                unsafe { *last_error = error_code; }
            }
            StringArray {
                strings: ptr::null_mut(),
                count: 0,
            }
        }
    }
}

/// Shows a single folder picker dialog with initial directory
/// initial_dir: C string with initial directory path (can be empty)
/// last_error: Out parameter to receive the last HRESULT on error
/// Returns: pointer to C string with selected folder path, or null on error/cancel
/// Caller must free the returned string using free_string()
#[unsafe(no_mangle)]
pub extern "C" fn show_folder_picker(initial_dir: *const c_char, last_error: *mut i32) -> *mut c_char {
    let initial_dir_str = unsafe { c_char_to_string(initial_dir) }.unwrap_or_default();
    let mut error_code = 0i32;

    match show_folder_picker_internal(&initial_dir_str, &mut error_code) {
        Ok(path) => {
            if path.is_empty() {
                // User cancelled - don't set error code for cancellation
                ptr::null_mut()
            } else {
                string_to_c_char(path)
            }
        },
        Err(_) => {
            if !last_error.is_null() {
                unsafe { *last_error = error_code; }
            }
            ptr::null_mut()
        }
    }
}

/// Shows a multiple folders picker dialog with initial directory
/// initial_dir: C string with initial directory path (can be empty)
/// last_error: Out parameter to receive the last HRESULT on error
/// Returns: StringArray structure with selected folder paths
/// Caller must free the returned array using free_string_array()
#[unsafe(no_mangle)]
pub extern "C" fn show_folders_picker(initial_dir: *const c_char, last_error: *mut i32) -> StringArray {
    let initial_dir_str = unsafe { c_char_to_string(initial_dir) }.unwrap_or_default();
    let mut error_code = 0i32;

    match show_folders_picker_internal(&initial_dir_str, &mut error_code) {
        Ok(paths) => create_string_array(paths),
        Err(_) => {
            if !last_error.is_null() {
                unsafe { *last_error = error_code; }
            }
            StringArray {
                strings: ptr::null_mut(),
                count: 0,
            }
        }
    }
}

/// Updates the taskbar progress for a specified window
/// hwnd: Window handle (HWND) as isize
/// completed: Amount of work completed
/// total: Total amount of work to be done
/// last_error: Out parameter to receive the last HRESULT on error
/// Returns: 0 on success, non-zero on failure
#[unsafe(no_mangle)]
pub extern "C" fn update_taskbar_progress(hwnd: isize, completed: u64, total: u64, last_error: *mut i32) -> i32 {
    let mut error_code = 0i32;

    match update_taskbar_progress_internal(hwnd, completed, total, &mut error_code) {
        Ok(_) => 0, // Success
        Err(_) => {
            if !last_error.is_null() {
                unsafe { *last_error = error_code; }
            }
            -1 // Failure
        }
    }
}

/// Frees a string allocated by the library
/// Must be called for every string returned by single picker functions
#[unsafe(no_mangle)]
pub extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

/// Frees a StringArray allocated by the library
/// Must be called for every StringArray returned by multiple picker functions
#[unsafe(no_mangle)]
pub extern "C" fn free_string_array(arr: StringArray) {
    if !arr.strings.is_null() && arr.count > 0 {
        unsafe {
            for i in 0..arr.count {
                let string_ptr: *mut _ = *arr.strings.offset(i as isize);
                if !string_ptr.is_null() {
                    let _ = CString::from_raw(string_ptr);
                }
            }
            // Free the array of pointers
            let _ = Vec::from_raw_parts(arr.strings, arr.count as usize, arr.count as usize);
        }
    }
}

// Relaunches a registered application (by its AUMID) with Administrator elevation (AO_ELEVATE).
//
// - `aumid` must be a null-terminated UTF-16 string pointer.
// - `arguments` may be null or a null-terminated UTF-16 string pointer.
// - `process_id_out` may be null or point to a u32 to receive the new process ID.
//
// Returns 0 (S_OK) on success or the raw HRESULT (as i32) on failure.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn relaunch_app_elevated(
    aumid: *const u16,
    arguments: *const u16,
    process_id_out: *mut u32,
) -> i32 {
    // Initialize COM on this thread
    let init_hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if init_hr.is_err() {
        return init_hr.0 as i32;
    }

    // Create the out-of-proc Activation Manager
    let inst = unsafe { CoCreateInstance::<Option<&IUnknown>, IApplicationActivationManager>(
        &ApplicationActivationManager,
        None,
        CLSCTX_LOCAL_SERVER,
    ) };

    // Might not work if Explorer.exe is not available like early in boot process

/*
	AO_NONE (0x00000000)
	AO_DESIGNMODE (0x00000001)
	AO_NOERRORUI (0x00000002)
	AO_NOSPLASHSCREEN (0x00000004)
	AO_PRELAUNCH (0x02000000)

	AO_BACKGROUNDTASK (0x00010000)
	AO_REMEDIATION (0x00080000)
	AO_TERMINATEBEFOREACTIVATE (0x00200000)
	AO_NOFOREGROUND (0x01000000)
	AO_NOMINSPLASHSCREENTIMER (0x04000000)
	AO_EXTENDEDTIMEOUT (0x08000000)
	AO_COMPONENT (0x10000000)
	AO_ELEVATE (0x20000000)
	AO_HOSTEDVIEW (0x40000000)
 */

    // Invoke ActivateApplication with AO_ELEVATE
    let hr = if let Ok(manager) = inst {
        match unsafe { manager.ActivateApplication(
            PCWSTR(aumid),
            PCWSTR(arguments),
            ACTIVATEOPTIONS(0x2000_0000), // AO_ELEVATE
        ) } {
            Ok(pid) => {
                if !process_id_out.is_null() {
                    unsafe { process_id_out.write(pid) };
                }
                0 // S_OK
            }
            Err(err) => err.code().0 as i32,
        }
    } else {
        inst.unwrap_err().code().0 as i32
    };

    // Uninitialize COM
    unsafe { CoUninitialize() };
    hr
}

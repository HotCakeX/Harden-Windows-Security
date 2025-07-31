use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Read;
use std::mem;
use std::os::raw::{c_char, c_int};
use std::path::Path;
use std::ptr;
use windows::{
    core::*, Win32::Foundation::HWND, Win32::System::Com::*,
    Win32::UI::Shell::Common::COMDLG_FILTERSPEC, Win32::UI::Shell::*,
};

// Region - BINARY SECURITY ANALYZER

// Sources
// https://learn.microsoft.com/windows/win32/debug/pe-format
// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-image_nt_headers32
// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-image_load_config_directory32
// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-image_optional_header32

const MSDOS_HEADER_SIG: u16 = 0x5A4D;
const PORTABLE_EXEC_SIG: u32 = 0x00004550;
const OPT_HDR_32_MAGIC: u16 = 0x010B;
const OPT_HDR_64_MAGIC: u16 = 0x020B;
const ARCH_X64_MACHINE: u16 = 0x8664;
const RELOCATIONS_REMOVED: u16 = 0x0001;
const ENTROPY_RANDOMIZATION: u16 = 0x0020;

// https://learn.microsoft.com/cpp/build/reference/dynamicbase-use-address-space-layout-randomization
// When we compile with /DYNAMICBASE, the linker sets the IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag (0x0040) in the PE header's characteristics field.
const BASE_ADDR_RANDOMIZATION: u16 = 0x0040;

const CONTROL_FLOW_PROTECTION: u16 = 0x4000;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum SecurityFeatureStatus {
    Disabled = 0,
    Enabled = 1,
    Unavailable = 2,
}

#[repr(C, packed)]
struct MsdosExecutableHeader {
    magic_signature: u16,
    last_page_bytes: u16,
    total_pages: u16,
    relocation_entries: u16,
    header_paragraphs: u16,
    minimum_paragraphs: u16,
    maximum_paragraphs: u16,
    stack_segment: u16,
    stack_pointer: u16,
    file_checksum: u16,
    instruction_pointer: u16,
    code_segment: u16,
    relocation_offset: u16,
    overlay_id: u16,
    reserved_area: [u16; 4],
    oem_id: u16,
    oem_data: u16,
    reserved_area2: [u16; 10],
    portable_header_offset: i32,
}

#[repr(C, packed)]
struct BinaryFileHeader {
    target_machine: u16,
    section_count: u16,
    creation_timestamp: u32,
    symbol_table_ptr: u32,
    symbol_count: u32,
    optional_header_size: u16,
    file_properties: u16,
}

#[repr(C, packed)]
struct DataDirectoryEntry {
    rva_address: u32,
    entry_size: u32,
}

#[repr(C, packed)]
struct OptionalExecutableHeader32 {
    header_magic: u16,
    linker_major_ver: u8,
    linker_minor_ver: u8,
    code_section_size: u32,
    initialized_data_size: u32,
    uninitialized_data_size: u32,
    entry_point_rva: u32,
    code_base_rva: u32,
    data_base_rva: u32,
    preferred_base_addr: u32,
    section_alignment: u32,
    file_alignment: u32,
    os_major_version: u16,
    os_minor_version: u16,
    image_major_version: u16,
    image_minor_version: u16,
    subsystem_major_version: u16,
    subsystem_minor_version: u16,
    win32_version: u32,
    total_image_size: u32,
    headers_size: u32,
    file_checksum: u32,
    target_subsystem: u16,
    runtime_characteristics: u16,
    stack_reserve_size: u32,
    stack_commit_size: u32,
    heap_reserve_size: u32,
    heap_commit_size: u32,
    loader_flags: u32,
    directory_entry_count: u32,
    directory_table: [DataDirectoryEntry; 16],
}

#[repr(C, packed)]
struct OptionalExecutableHeader64 {
    header_magic: u16,
    linker_major_ver: u8,
    linker_minor_ver: u8,
    code_section_size: u32,
    initialized_data_size: u32,
    uninitialized_data_size: u32,
    entry_point_rva: u32,
    code_base_rva: u32,
    preferred_base_addr: u64,
    section_alignment: u32,
    file_alignment: u32,
    os_major_version: u16,
    os_minor_version: u16,
    image_major_version: u16,
    image_minor_version: u16,
    subsystem_major_version: u16,
    subsystem_minor_version: u16,
    win32_version: u32,
    total_image_size: u32,
    headers_size: u32,
    file_checksum: u32,
    target_subsystem: u16,
    runtime_characteristics: u16,
    stack_reserve_size: u64,
    stack_commit_size: u64,
    heap_reserve_size: u64,
    heap_commit_size: u64,
    loader_flags: u32,
    directory_entry_count: u32,
    directory_table: [DataDirectoryEntry; 16],
}

#[repr(C)]
pub struct SecurityAnalysisResult {
    pub binary_path: *mut c_char,
    pub address_randomization: SecurityFeatureStatus,
    pub entropy_randomization: SecurityFeatureStatus,
    pub flow_protection: SecurityFeatureStatus,
    pub error_code: c_int,
    pub error_message: *mut c_char,
}

#[repr(C)]
pub struct SecurityAnalysisCollection {
    pub analysis_results: *mut SecurityAnalysisResult,
    pub total_count: c_int,
}

struct BinarySecurityAnalyzer {
    binary_content: Vec<u8>,
}

impl BinarySecurityAnalyzer {
    fn initialize_from_file(binary_path: &str) -> std::io::Result<Self> {
        let mut file_handle: File = File::open(binary_path)?;
        let mut binary_content: Vec<u8> = Vec::new();
        file_handle.read_to_end(&mut binary_content)?;

        Ok(Self { binary_content })
    }

    fn perform_security_analysis(
        &mut self,
        binary_path: &str,
    ) -> (
        String,
        SecurityFeatureStatus,
        SecurityFeatureStatus,
        SecurityFeatureStatus,
        i32,
        String,
    ) {
        if self.binary_content.len() < mem::size_of::<MsdosExecutableHeader>() {
            return (
                binary_path.to_string(),
                SecurityFeatureStatus::Disabled,
                SecurityFeatureStatus::Unavailable,
                SecurityFeatureStatus::Disabled,
                1001,
                "Binary file too small for DOS header".to_string(),
            );
        }

        let msdos_header: MsdosExecutableHeader =
            self.extract_structure::<MsdosExecutableHeader>(0);
        if msdos_header.magic_signature != MSDOS_HEADER_SIG {
            return (
                binary_path.to_string(),
                SecurityFeatureStatus::Disabled,
                SecurityFeatureStatus::Unavailable,
                SecurityFeatureStatus::Disabled,
                1002,
                "Invalid DOS signature".to_string(),
            );
        }

        if msdos_header.portable_header_offset < 0
            || (msdos_header.portable_header_offset as usize) >= self.binary_content.len()
        {
            return (
                binary_path.to_string(),
                SecurityFeatureStatus::Disabled,
                SecurityFeatureStatus::Unavailable,
                SecurityFeatureStatus::Disabled,
                1003,
                "Invalid PE header offset".to_string(),
            );
        }

        let pe_header_position: usize = msdos_header.portable_header_offset as usize;
        if pe_header_position + 4 > self.binary_content.len() {
            return (
                binary_path.to_string(),
                SecurityFeatureStatus::Disabled,
                SecurityFeatureStatus::Unavailable,
                SecurityFeatureStatus::Disabled,
                1004,
                "Binary truncated at PE signature".to_string(),
            );
        }

        let pe_signature: u32 = u32::from_le_bytes([
            self.binary_content[pe_header_position],
            self.binary_content[pe_header_position + 1],
            self.binary_content[pe_header_position + 2],
            self.binary_content[pe_header_position + 3],
        ]);

        if pe_signature != PORTABLE_EXEC_SIG {
            return (
                binary_path.to_string(),
                SecurityFeatureStatus::Disabled,
                SecurityFeatureStatus::Unavailable,
                SecurityFeatureStatus::Disabled,
                1005,
                "Invalid PE signature".to_string(),
            );
        }

        let file_header_position: usize = pe_header_position + 4;
        if file_header_position + mem::size_of::<BinaryFileHeader>() > self.binary_content.len() {
            return (
                binary_path.to_string(),
                SecurityFeatureStatus::Disabled,
                SecurityFeatureStatus::Unavailable,
                SecurityFeatureStatus::Disabled,
                1006,
                "Binary truncated at file header".to_string(),
            );
        }

        let file_header: BinaryFileHeader =
            self.extract_structure::<BinaryFileHeader>(file_header_position);
        let is_x64_architecture: bool = file_header.target_machine == ARCH_X64_MACHINE;

        let optional_header_position: usize =
            file_header_position + mem::size_of::<BinaryFileHeader>();
        if optional_header_position + 2 > self.binary_content.len() {
            return (
                binary_path.to_string(),
                SecurityFeatureStatus::Disabled,
                SecurityFeatureStatus::Unavailable,
                SecurityFeatureStatus::Disabled,
                1007,
                "Binary truncated at optional header".to_string(),
            );
        }

        let header_magic: u16 = u16::from_le_bytes([
            self.binary_content[optional_header_position],
            self.binary_content[optional_header_position + 1],
        ]);

        if header_magic == 0 {
            return (
                binary_path.to_string(),
                SecurityFeatureStatus::Disabled,
                SecurityFeatureStatus::Unavailable,
                SecurityFeatureStatus::Disabled,
                1008,
                "Invalid optional header magic".to_string(),
            );
        }

        let (runtime_flags, is_managed_code): (u16, bool) = match header_magic {
            OPT_HDR_32_MAGIC => {
                if optional_header_position + mem::size_of::<OptionalExecutableHeader32>()
                    > self.binary_content.len()
                {
                    return (
                        binary_path.to_string(),
                        SecurityFeatureStatus::Disabled,
                        SecurityFeatureStatus::Unavailable,
                        SecurityFeatureStatus::Disabled,
                        1009,
                        "Binary truncated at 32-bit optional header".to_string(),
                    );
                }
                let optional_header: OptionalExecutableHeader32 =
                    self.extract_structure::<OptionalExecutableHeader32>(optional_header_position);
                let managed_runtime: bool = optional_header.directory_table[14].rva_address != 0;
                (optional_header.runtime_characteristics, managed_runtime)
            }
            OPT_HDR_64_MAGIC => {
                if optional_header_position + mem::size_of::<OptionalExecutableHeader64>()
                    > self.binary_content.len()
                {
                    return (
                        binary_path.to_string(),
                        SecurityFeatureStatus::Disabled,
                        SecurityFeatureStatus::Unavailable,
                        SecurityFeatureStatus::Disabled,
                        1010,
                        "Binary truncated at 64-bit optional header".to_string(),
                    );
                }
                let optional_header: OptionalExecutableHeader64 =
                    self.extract_structure::<OptionalExecutableHeader64>(optional_header_position);
                let managed_runtime: bool = optional_header.directory_table[14].rva_address != 0;
                (optional_header.runtime_characteristics, managed_runtime)
            }
            _ => {
                return (
                    binary_path.to_string(),
                    SecurityFeatureStatus::Disabled,
                    SecurityFeatureStatus::Unavailable,
                    SecurityFeatureStatus::Disabled,
                    1011,
                    "Unknown optional header format".to_string(),
                );
            }
        };

        // Extract runtime protection capabilities
        let has_base_randomization: bool = runtime_flags & BASE_ADDR_RANDOMIZATION != 0;
        let has_entropy_randomization: bool = runtime_flags & ENTROPY_RANDOMIZATION != 0;
        let has_flow_protection: bool = runtime_flags & CONTROL_FLOW_PROTECTION != 0;

        // Evaluate address space layout randomization
        let address_randomization: SecurityFeatureStatus = if has_base_randomization {
            let _relocations_stripped: bool =
                file_header.file_properties & RELOCATIONS_REMOVED != 0;
            SecurityFeatureStatus::Enabled
        } else {
            SecurityFeatureStatus::Disabled
        };

        // Evaluate high entropy virtual addressing
        let entropy_randomization: SecurityFeatureStatus = if is_x64_architecture {
            if has_entropy_randomization {
                SecurityFeatureStatus::Enabled
            } else {
                SecurityFeatureStatus::Disabled
            }
        } else {
            SecurityFeatureStatus::Unavailable
        };

        // Evaluate control flow protection
        let flow_protection: SecurityFeatureStatus = if is_managed_code {
            SecurityFeatureStatus::Unavailable
        } else if has_flow_protection {
            SecurityFeatureStatus::Enabled
        } else {
            SecurityFeatureStatus::Disabled
        };

        (
            binary_path.to_string(),
            address_randomization,
            entropy_randomization,
            flow_protection,
            0,
            "Success".to_string(),
        )
    }

    fn extract_structure<T>(&self, byte_offset: usize) -> T {
        unsafe {
            let data_ptr: *const T = self.binary_content.as_ptr().add(byte_offset) as *const T;
            std::ptr::read_unaligned(data_ptr)
        }
    }
}

pub fn scan_directory_for_binaries(directory_path: &str) -> std::io::Result<()> {
    let binary_files: Vec<String> = discover_binaries_recursively(directory_path)?;

    for binary_file in binary_files {
        match BinarySecurityAnalyzer::initialize_from_file(&binary_file) {
            Ok(mut analyzer) => {
                let (_, _, _, _, _, _) = analyzer.perform_security_analysis(&binary_file);
            }
            Err(e) => eprintln!("Error analyzing {}: {}", binary_file, e),
        }
    }

    Ok(())
}

fn discover_binaries_recursively(root_directory: &str) -> std::io::Result<Vec<String>> {
    use std::fs;
    let mut binary_files: Vec<String> = Vec::new();

    fn traverse_directory(current_dir: &Path, file_list: &mut Vec<String>) -> std::io::Result<()> {
        if current_dir.is_dir() {
            for dir_entry in fs::read_dir(current_dir)? {
                let dir_entry = dir_entry?;
                let entry_path: std::path::PathBuf = dir_entry.path();
                if entry_path.is_dir() {
                    traverse_directory(&entry_path, file_list)?;
                } else if let Some(file_extension) = entry_path.extension() {
                    if file_extension == "exe" || file_extension == "dll" {
                        if let Some(path_string) = entry_path.to_str() {
                            file_list.push(path_string.to_string());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    traverse_directory(Path::new(root_directory), &mut binary_files)?;
    Ok(binary_files)
}

fn create_fallback_error_result(file_path: &str) -> SecurityAnalysisResult {
    // Creating fallback strings that are guaranteed to not fail, preventing any memory leaks.
    let binary_path_c: *mut c_char = CString::new(file_path)
        .unwrap_or_else(|_| CString::new("Invalid path").unwrap())
        .into_raw();
    let error_message_c: *mut c_char = CString::new("String encoding error").unwrap().into_raw();

    SecurityAnalysisResult {
        binary_path: binary_path_c,
        address_randomization: SecurityFeatureStatus::Disabled,
        entropy_randomization: SecurityFeatureStatus::Unavailable,
        flow_protection: SecurityFeatureStatus::Disabled,
        error_code: 3001,
        error_message: error_message_c,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn scan_directory_via_interop(
    directory_path: *const c_char,
) -> *mut SecurityAnalysisCollection {
    if directory_path.is_null() {
        return std::ptr::null_mut();
    }

    let c_string: &CStr = unsafe { CStr::from_ptr(directory_path) };
    let target_path: &str = match c_string.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let discovered_files: std::io::Result<Vec<String>> = discover_binaries_recursively(target_path);

    let binary_files: Vec<String> = match discovered_files {
        Ok(files) => files,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut analysis_results: Vec<SecurityAnalysisResult> = Vec::new();

    for file_path in binary_files {
        let (
            binary_path,
            address_randomization,
            entropy_randomization,
            flow_protection,
            error_code,
            error_message,
        ) = match BinarySecurityAnalyzer::initialize_from_file(&file_path) {
            Ok(mut analyzer) => analyzer.perform_security_analysis(&file_path),
            Err(e) => (
                file_path.clone(),
                SecurityFeatureStatus::Disabled,
                SecurityFeatureStatus::Disabled,
                SecurityFeatureStatus::Disabled,
                2001,
                format!("File access error: {}", e),
            ),
        };

        // Try to create CStrings, but if any fail, create a fallback error result
        let binary_path_c: *mut c_char = match CString::new(binary_path) {
            Ok(s) => s.into_raw(),
            Err(_) => {
                analysis_results.push(create_fallback_error_result(&file_path));
                continue;
            }
        };

        let error_message_c: *mut c_char = match CString::new(error_message) {
            Ok(s) => s.into_raw(),
            Err(_) => {
                unsafe {
                    let _ = CString::from_raw(binary_path_c);
                }
                analysis_results.push(create_fallback_error_result(&file_path));
                continue;
            }
        };

        analysis_results.push(SecurityAnalysisResult {
            binary_path: binary_path_c,
            address_randomization,
            entropy_randomization,
            flow_protection,
            error_code,
            error_message: error_message_c,
        });
    }

    let result_count: c_int = analysis_results.len() as c_int;
    let results_ptr: *mut SecurityAnalysisResult = analysis_results.as_mut_ptr();
    std::mem::forget(analysis_results);

    let security_analysis_collection: Box<SecurityAnalysisCollection> =
        Box::new(SecurityAnalysisCollection {
            analysis_results: results_ptr,
            total_count: result_count,
        });

    Box::into_raw(security_analysis_collection)
}

#[unsafe(no_mangle)]
pub extern "C" fn release_analysis_results(results: *mut SecurityAnalysisCollection) {
    if results.is_null() {
        return;
    }

    unsafe {
        let analysis_collection: Box<SecurityAnalysisCollection> = Box::from_raw(results);

        for i in 0..analysis_collection.total_count {
            let result: *mut SecurityAnalysisResult =
                analysis_collection.analysis_results.add(i as usize);

            if !(*result).binary_path.is_null() {
                let _ = CString::from_raw((*result).binary_path);
            }
            if !(*result).error_message.is_null() {
                let _ = CString::from_raw((*result).error_message);
            }
        }

        if !analysis_collection.analysis_results.is_null() {
            let _ = Vec::from_raw_parts(
                analysis_collection.analysis_results,
                analysis_collection.total_count as usize,
                analysis_collection.total_count as usize,
            );
        }
    }
}

// End Region - BINARY SECURITY ANALYZER


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

    let count: i32 = paths.len() as i32;
    let mut c_strings: Vec<*mut c_char> = paths.into_iter().map(string_to_c_char).collect();

    // Allocate memory for the array of string pointers
    let strings_ptr: *mut *mut c_char = c_strings.as_mut_ptr();
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

    let mut specs: Vec<COMDLG_FILTERSPEC> = Vec::new();
    let mut name_bufs: Vec<Box<[u16]>> = Vec::new();
    let mut spec_bufs: Vec<Box<[u16]>> = Vec::new();

    // Split to get pairs of description and pattern
    let parts: Vec<&str> = filter_str.split('|').collect();

    // Process pairs (description, pattern)
    for chunk in parts.chunks(2) {
        if chunk.len() == 2 {
            let description: &str = chunk[0];
            let pattern: &str = chunk[1];

            // Convert to wide strings (UTF-16) with terminating NUL
            let desc_wide: Vec<u16> = description
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>();
            let pattern_wide: Vec<u16> = pattern
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>();

            // Move into boxed slices so they own their memory
            let desc_box: Box<[u16]> = desc_wide.into_boxed_slice();
            let pattern_box: Box<[u16]> = pattern_wide.into_boxed_slice();

            // Get raw pointers for COMDLG_FILTERSPEC
            let desc_ptr: *const u16 = desc_box.as_ptr();
            let pattern_ptr: *const u16 = pattern_box.as_ptr();

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

// Function to set initial directory for both IFileOpenDialog and IFileSaveDialog
fn set_initial_directory<T>(dialog: &T, initial_dir: &str) -> Result<()>
where
    T: windows::core::Interface,
{
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
            // Try to cast to IFileDialog interface
            if let Ok(file_dialog) = dialog.cast::<IFileDialog>() {
                let _ = file_dialog.SetFolder(&shell_item);
            }
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
fn show_file_picker_internal(
    filter: &str,
    initial_dir: &str,
    last_error: &mut i32,
) -> Result<String> {
    unsafe {
        let init_hr: HRESULT = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if init_hr.is_err() {
            *last_error = init_hr.0;
            return Err(Error::from(init_hr));
        }

        let file_dialog: IFileOpenDialog =
            match CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) {
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

        let show_result: Result<()> = file_dialog.Show(None);
        if let Err(err) = show_result {
            let hresult: i32 = err.code().0;
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

// Internal function to show save file dialog
fn show_save_file_dialog_internal(
    filter: &str,
    initial_dir: &str,
    default_filename: &str,
    last_error: &mut i32,
) -> Result<String> {
    unsafe {
        let init_hr: HRESULT = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if init_hr.is_err() {
            *last_error = init_hr.0;
            return Err(Error::from(init_hr));
        }

        let file_dialog: IFileSaveDialog =
            match CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER) {
                Ok(dialog) => dialog,
                Err(err) => {
                    *last_error = err.code().0;
                    CoUninitialize();
                    return Err(err);
                }
            };

        if let Err(err) = file_dialog.SetTitle(w!("Save File As")) {
            *last_error = err.code().0;
            CoUninitialize();
            return Err(err);
        }

        if let Err(err) = set_initial_directory(&file_dialog, initial_dir) {
            *last_error = err.code().0;
            CoUninitialize();
            return Err(err);
        }

        // Set default filename if provided
        if !default_filename.is_empty() {
            let wide_filename: Vec<u16> = default_filename
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            if let Err(err) = file_dialog.SetFileName(PCWSTR(wide_filename.as_ptr())) {
                *last_error = err.code().0;
                CoUninitialize();
                return Err(err);
            }
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

        let show_result: Result<()> = file_dialog.Show(None);
        if let Err(err) = show_result {
            let hresult: i32 = err.code().0;
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
fn show_files_picker_internal(
    filter: &str,
    initial_dir: &str,
    last_error: &mut i32,
) -> Result<Vec<String>> {
    unsafe {
        let init_hr: HRESULT = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if init_hr.is_err() {
            *last_error = init_hr.0;
            return Err(Error::from(init_hr));
        }

        let file_dialog: IFileOpenDialog =
            match CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) {
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

        let show_result: Result<()> = file_dialog.Show(None);
        if let Err(err) = show_result {
            let hresult: i32 = err.code().0;
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
        let init_hr: HRESULT = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if init_hr.is_err() {
            *last_error = init_hr.0;
            return Err(Error::from(init_hr));
        }

        let file_dialog: IFileOpenDialog =
            match CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) {
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

        let show_result: Result<()> = file_dialog.Show(None);
        if let Err(err) = show_result {
            let hresult: i32 = err.code().0;
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
        let init_hr: HRESULT = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if init_hr.is_err() {
            *last_error = init_hr.0;
            return Err(Error::from(init_hr));
        }

        let file_dialog: IFileOpenDialog =
            match CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) {
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

        let show_result: Result<()> = file_dialog.Show(None);
        if let Err(err) = show_result {
            let hresult: i32 = err.code().0;
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
fn update_taskbar_progress_internal(
    hwnd: isize,
    completed: u64,
    total: u64,
    last_error: &mut i32,
) -> Result<()> {
    unsafe {
        // Try to initialize COM, but don't fail if it's already initialized
        let init_hr: HRESULT = CoInitializeEx(None, COINIT_APARTMENTTHREADED);

        // Check if initialization succeeded or if COM was already initialized
        let should_uninitialize: bool = if init_hr.is_ok() {
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
        let taskbar_list: ITaskbarList3 =
            match CoCreateInstance(&CLSID_TASKBARLIST, None, CLSCTX_INPROC_SERVER) {
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
        let hwnd_handle: HWND = HWND(hwnd as *mut std::ffi::c_void);
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
pub extern "C" fn show_file_picker(
    filter: *const c_char,
    initial_dir: *const c_char,
    last_error: *mut i32,
) -> *mut c_char {
    let filter_str: String = unsafe { c_char_to_string(filter) }.unwrap_or_default();
    let initial_dir_str: String = unsafe { c_char_to_string(initial_dir) }.unwrap_or_default();
    let mut error_code: i32 = 0i32;

    let result: *mut c_char =
        match show_file_picker_internal(&filter_str, &initial_dir_str, &mut error_code) {
            Ok(path) => {
                if path.is_empty() {
                    // User cancelled - don't set error code for cancellation
                    ptr::null_mut()
                } else {
                    string_to_c_char(path)
                }
            }
            Err(_) => {
                if !last_error.is_null() {
                    unsafe {
                        *last_error = error_code;
                    }
                }
                ptr::null_mut()
            }
        };

    result
}

/// Shows a save file dialog with filter, initial directory, and default filename
/// filter: C string with filter format "Description|*.ext|Description2|*.ext2"
/// initial_dir: C string with initial directory path (can be empty)
/// default_filename: C string with default filename (can be empty)
/// last_error: Out parameter to receive the last HRESULT on error
/// Returns: pointer to C string with save file path, or null on error/cancel
/// Caller must free the returned string using free_string()
#[unsafe(no_mangle)]
pub extern "C" fn show_save_file_dialog(
    filter: *const c_char,
    initial_dir: *const c_char,
    default_filename: *const c_char,
    last_error: *mut i32,
) -> *mut c_char {
    let filter_str: String = unsafe { c_char_to_string(filter) }.unwrap_or_default();
    let initial_dir_str: String = unsafe { c_char_to_string(initial_dir) }.unwrap_or_default();
    let default_filename_str: String =
        unsafe { c_char_to_string(default_filename) }.unwrap_or_default();
    let mut error_code: i32 = 0i32;

    let result: *mut c_char = match show_save_file_dialog_internal(
        &filter_str,
        &initial_dir_str,
        &default_filename_str,
        &mut error_code,
    ) {
        Ok(path) => {
            if path.is_empty() {
                // User cancelled - don't set error code for cancellation
                ptr::null_mut()
            } else {
                string_to_c_char(path)
            }
        }
        Err(_) => {
            if !last_error.is_null() {
                unsafe {
                    *last_error = error_code;
                }
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
pub extern "C" fn show_files_picker(
    filter: *const c_char,
    initial_dir: *const c_char,
    last_error: *mut i32,
) -> StringArray {
    let filter_str: String = unsafe { c_char_to_string(filter) }.unwrap_or_default();
    let initial_dir_str: String = unsafe { c_char_to_string(initial_dir) }.unwrap_or_default();
    let mut error_code: i32 = 0i32;

    match show_files_picker_internal(&filter_str, &initial_dir_str, &mut error_code) {
        Ok(paths) => create_string_array(paths),
        Err(_) => {
            if !last_error.is_null() {
                unsafe {
                    *last_error = error_code;
                }
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
pub extern "C" fn show_folder_picker(
    initial_dir: *const c_char,
    last_error: *mut i32,
) -> *mut c_char {
    let initial_dir_str: String = unsafe { c_char_to_string(initial_dir) }.unwrap_or_default();
    let mut error_code: i32 = 0i32;

    match show_folder_picker_internal(&initial_dir_str, &mut error_code) {
        Ok(path) => {
            if path.is_empty() {
                // User cancelled - don't set error code for cancellation
                ptr::null_mut()
            } else {
                string_to_c_char(path)
            }
        }
        Err(_) => {
            if !last_error.is_null() {
                unsafe {
                    *last_error = error_code;
                }
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
pub extern "C" fn show_folders_picker(
    initial_dir: *const c_char,
    last_error: *mut i32,
) -> StringArray {
    let initial_dir_str: String = unsafe { c_char_to_string(initial_dir) }.unwrap_or_default();
    let mut error_code: i32 = 0i32;

    match show_folders_picker_internal(&initial_dir_str, &mut error_code) {
        Ok(paths) => create_string_array(paths),
        Err(_) => {
            if !last_error.is_null() {
                unsafe {
                    *last_error = error_code;
                }
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
pub extern "C" fn update_taskbar_progress(
    hwnd: isize,
    completed: u64,
    total: u64,
    last_error: *mut i32,
) -> i32 {
    let mut error_code: i32 = 0i32;

    match update_taskbar_progress_internal(hwnd, completed, total, &mut error_code) {
        Ok(_) => 0, // Success
        Err(_) => {
            if !last_error.is_null() {
                unsafe {
                    *last_error = error_code;
                }
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
    let init_hr: HRESULT = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if init_hr.is_err() {
        return init_hr.0 as i32;
    }

    // Create the out-of-proc Activation Manager
    let inst: Result<IApplicationActivationManager> = unsafe {
        CoCreateInstance::<Option<&IUnknown>, IApplicationActivationManager>(
            &ApplicationActivationManager,
            None,
            CLSCTX_LOCAL_SERVER,
        )
    };

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
    let hr: i32 = if let Ok(manager) = inst {
        match unsafe {
            manager.ActivateApplication(
                PCWSTR(aumid),
                PCWSTR(arguments),
                ACTIVATEOPTIONS(0x2000_0000), // AO_ELEVATE
            )
        } {
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

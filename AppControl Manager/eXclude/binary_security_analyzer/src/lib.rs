use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Result};
use std::mem;
use std::os::raw::{c_char, c_int};
use std::path::Path;

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
    fn initialize_from_file(binary_path: &str) -> Result<Self> {
        let mut file_handle = File::open(binary_path)?;
        let mut binary_content = Vec::new();
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

        let msdos_header = self.extract_structure::<MsdosExecutableHeader>(0);
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

        let pe_header_position = msdos_header.portable_header_offset as usize;
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

        let pe_signature = u32::from_le_bytes([
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

        let file_header_position = pe_header_position + 4;
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

        let file_header = self.extract_structure::<BinaryFileHeader>(file_header_position);
        let is_x64_architecture = file_header.target_machine == ARCH_X64_MACHINE;

        let optional_header_position = file_header_position + mem::size_of::<BinaryFileHeader>();
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

        let header_magic = u16::from_le_bytes([
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

        let (runtime_flags, is_managed_code) = match header_magic {
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
                let optional_header =
                    self.extract_structure::<OptionalExecutableHeader32>(optional_header_position);
                let managed_runtime = optional_header.directory_table[14].rva_address != 0;
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
                let optional_header =
                    self.extract_structure::<OptionalExecutableHeader64>(optional_header_position);
                let managed_runtime = optional_header.directory_table[14].rva_address != 0;
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
        let has_base_randomization = runtime_flags & BASE_ADDR_RANDOMIZATION != 0;
        let has_entropy_randomization = runtime_flags & ENTROPY_RANDOMIZATION != 0;
        let has_flow_protection = runtime_flags & CONTROL_FLOW_PROTECTION != 0;

        // Evaluate address space layout randomization
        let address_randomization = if has_base_randomization {
            let _relocations_stripped = file_header.file_properties & RELOCATIONS_REMOVED != 0;
            SecurityFeatureStatus::Enabled
        } else {
            SecurityFeatureStatus::Disabled
        };

        // Evaluate high entropy virtual addressing
        let entropy_randomization = if is_x64_architecture {
            if has_entropy_randomization {
                SecurityFeatureStatus::Enabled
            } else {
                SecurityFeatureStatus::Disabled
            }
        } else {
            SecurityFeatureStatus::Unavailable
        };

        // Evaluate control flow protection
        let flow_protection = if is_managed_code {
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
            let data_ptr = self.binary_content.as_ptr().add(byte_offset) as *const T;
            std::ptr::read_unaligned(data_ptr)
        }
    }
}

pub fn scan_directory_for_binaries(directory_path: &str) -> Result<()> {
    let binary_files = discover_binaries_recursively(directory_path)?;

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

fn discover_binaries_recursively(root_directory: &str) -> Result<Vec<String>> {
    use std::fs;
    let mut binary_files = Vec::new();

    fn traverse_directory(current_dir: &Path, file_list: &mut Vec<String>) -> Result<()> {
        if current_dir.is_dir() {
            for dir_entry in fs::read_dir(current_dir)? {
                let dir_entry = dir_entry?;
                let entry_path = dir_entry.path();
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
    let binary_path_c = CString::new(file_path)
        .unwrap_or_else(|_| CString::new("Invalid path").unwrap())
        .into_raw();
    let error_message_c = CString::new("String encoding error").unwrap().into_raw();

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

    let c_string = unsafe { CStr::from_ptr(directory_path) };
    let target_path = match c_string.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let discovered_files = discover_binaries_recursively(target_path);

    let binary_files = match discovered_files {
        Ok(files) => files,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut analysis_results = Vec::new();

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
        let binary_path_c = match CString::new(binary_path) {
            Ok(s) => s.into_raw(),
            Err(_) => {
                analysis_results.push(create_fallback_error_result(&file_path));
                continue;
            }
        };

        let error_message_c = match CString::new(error_message) {
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

    let result_count = analysis_results.len() as c_int;
    let results_ptr = analysis_results.as_mut_ptr();
    std::mem::forget(analysis_results);

    let security_analysis_collection = Box::new(SecurityAnalysisCollection {
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
        let analysis_collection = Box::from_raw(results);

        for i in 0..analysis_collection.total_count {
            let result = analysis_collection.analysis_results.add(i as usize);

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

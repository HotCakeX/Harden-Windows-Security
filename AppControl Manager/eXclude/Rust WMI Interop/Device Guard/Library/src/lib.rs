#![allow(non_snake_case)]

use std::{ffi::CString, os::raw::c_char};

use serde::Serialize;
use windows::{
    Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoInitializeSecurity, EOAC_NONE, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        SAFEARRAY,
    },
    Win32::System::Ole::{SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound},
    Win32::System::Variant::*,
    Win32::System::Wmi::*,
    core::*,
};

/// Converts a BSTR to an `Option<String>`.
/// If the converted string is empty, returns `None`; otherwise returns `Some` with the string.
fn bstr_to_option(bstr: &BSTR) -> Option<String> {
    let s = bstr.to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// A structure representing the properties exposed by the Win32_DeviceGuard WMI class,
/// which is found in the "root\\Microsoft\\Windows\\DeviceGuard" namespace.
/// The order of fields corresponds to the printed output of the retrieved data.
#[derive(Debug, Default, Serialize)]
pub struct DeviceGuard {
    pub __PATH: Option<String>,
    pub __NAMESPACE: Option<String>,
    pub __SERVER: Option<String>,
    pub __DERIVATION: Option<String>,
    pub __PROPERTY_COUNT: Option<i32>,
    pub __RELPATH: Option<String>,
    pub __DYNASTY: Option<String>,
    pub __SUPERCLASS: Option<String>,
    pub __CLASS: Option<String>,
    pub __GENUS: Option<i32>,
    pub AvailableSecurityProperties: Option<Vec<String>>,
    pub CodeIntegrityPolicyEnforcementStatus: Option<i32>,
    pub InstanceIdentifier: Option<String>,
    pub RequiredSecurityProperties: Option<Vec<String>>,
    pub SecurityFeaturesEnabled: Option<Vec<String>>,
    pub SecurityServicesConfigured: Option<Vec<String>>,
    pub SecurityServicesRunning: Option<Vec<String>>,
    pub SmmIsolationLevel: Option<u8>,
    pub UsermodeCodeIntegrityPolicyEnforcementStatus: Option<i32>,
    pub Version: Option<String>,
    pub VirtualizationBasedSecurityStatus: Option<i32>,
    pub VirtualMachineIsolation: Option<bool>,
    pub VirtualMachineIsolationProperties: Option<Vec<String>>,
}

impl DeviceGuard {
    /// Decodes a SAFEARRAY containing 16-bit integers (VT_ARRAY|VT_I2) into a vector of strings.
    ///
    /// It retrieves the lower and upper bounds of the SAFEARRAY and iterates
    /// through each index, converting the integer at that index to a string.
    /// Returns `None` if any step fails.
    unsafe fn decode_i16_array(parray: *mut SAFEARRAY) -> Option<Vec<String>> {
        // Get the lower and upper bounds of the array.
        let lbound = unsafe { SafeArrayGetLBound(parray, 1) }.ok()?;
        let ubound = unsafe { SafeArrayGetUBound(parray, 1) }.ok()?;
        let mut result = Vec::new();

        // Iterate over the array elements.
        for i in lbound..=ubound {
            let mut val: i16 = 0;
            // SafeArrayGetElement requires a pointer to the index and a pointer to the value.
            // Here we pass the address of `i` and use transmute on the address of `val`.
            unsafe { SafeArrayGetElement(parray, &i, std::mem::transmute(&mut val)) }.ok()?;
            result.push(val.to_string());
        }
        Some(result)
    }

    /// Sets an appropriate property of the `DeviceGuard` struct based on the provided property name and VARIANT value.
    ///
    /// For properties of type VT_BSTR (value 8), `bstr_to_option` is used to convert the BSTR.
    /// For properties that are an array of 16-bit integers (VT_ARRAY|VT_I2 with value 8195),
    /// the `decode_i16_array` helper function is used to convert the array to a vector of strings.
    ///
    unsafe fn set_property(&mut self, name: &str, var: &VARIANT) {
        match name {
            // Each branch verifies the variant's type before processing.
            "__PATH" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__PATH =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            "__NAMESPACE" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__NAMESPACE =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            "__SERVER" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__SERVER =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            "__DERIVATION" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8200 {
                    self.__DERIVATION =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            "__PROPERTY_COUNT" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.__PROPERTY_COUNT = Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "__RELPATH" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__RELPATH =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            "__DYNASTY" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__DYNASTY =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            "__SUPERCLASS" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 1 {
                    self.__SUPERCLASS = None;
                }
            }
            "__CLASS" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__CLASS =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            "__GENUS" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.__GENUS = Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "AvailableSecurityProperties" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8195 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.AvailableSecurityProperties =
                            unsafe { DeviceGuard::decode_i16_array(parray) };
                    }
                }
            }
            "CodeIntegrityPolicyEnforcementStatus" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.CodeIntegrityPolicyEnforcementStatus =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "InstanceIdentifier" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.InstanceIdentifier =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            "RequiredSecurityProperties" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8195 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.RequiredSecurityProperties =
                            unsafe { DeviceGuard::decode_i16_array(parray) };
                    }
                } else {
                    self.RequiredSecurityProperties =
                        unsafe { bstr_to_option(&var.Anonymous.Anonymous.Anonymous.bstrVal) }
                            .map(|s| vec![s]);
                }
            }
            "SecurityFeaturesEnabled" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8195 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.SecurityFeaturesEnabled =
                            unsafe { DeviceGuard::decode_i16_array(parray) };
                    }
                } else {
                    self.SecurityFeaturesEnabled =
                        unsafe { bstr_to_option(&var.Anonymous.Anonymous.Anonymous.bstrVal) }
                            .map(|s| vec![s]);
                }
            }
            "SecurityServicesConfigured" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8195 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.SecurityServicesConfigured =
                            unsafe { DeviceGuard::decode_i16_array(parray) };
                    }
                } else {
                    self.SecurityServicesConfigured =
                        unsafe { bstr_to_option(&var.Anonymous.Anonymous.Anonymous.bstrVal) }
                            .map(|s| vec![s]);
                }
            }
            "SecurityServicesRunning" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8195 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.SecurityServicesRunning =
                            unsafe { DeviceGuard::decode_i16_array(parray) };
                    }
                } else {
                    self.SecurityServicesRunning =
                        unsafe { bstr_to_option(&var.Anonymous.Anonymous.Anonymous.bstrVal) }
                            .map(|s| vec![s]);
                }
            }
            "SmmIsolationLevel" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.SmmIsolationLevel =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "UsermodeCodeIntegrityPolicyEnforcementStatus" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.UsermodeCodeIntegrityPolicyEnforcementStatus =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "Version" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    unsafe {
                        self.Version = bstr_to_option(&var.Anonymous.Anonymous.Anonymous.bstrVal)
                    };
                }
            }
            "VirtualizationBasedSecurityStatus" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.VirtualizationBasedSecurityStatus =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "VirtualMachineIsolation" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.VirtualMachineIsolation =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "VirtualMachineIsolationProperties" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8195 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.VirtualMachineIsolationProperties =
                            unsafe { DeviceGuard::decode_i16_array(parray) };
                    }
                } else {
                    self.VirtualMachineIsolationProperties =
                        unsafe { bstr_to_option(&var.Anonymous.Anonymous.Anonymous.bstrVal) }
                            .map(|s| vec![s]);
                }
            }
            _ => {}
        }
    }
}

/// Queries the Win32_DeviceGuard WMI class and returns a populated `DeviceGuard` struct.
///
/// This function initializes COM in multi-threaded mode, sets up the security for COM,
/// obtains the WMI locator, connects to the "root\\Microsoft\\Windows\\DeviceGuard" namespace,
/// executes the WQL query, and iterates over the returned object properties to fill in the struct.
fn query_device_guard() -> DeviceGuard {
    unsafe {
        // Initialize COM for use in multi-threaded applications.
        CoInitializeEx(None, COINIT_MULTITHREADED)
            .ok()
            .expect("CoInitializeEx failed");

        // Set the COM security levels.
        CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )
        .ok()
        .expect("CoInitializeSecurity failed");

        // Create an instance of the WMI locator.
        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
            .expect("Failed to create IWbemLocator instance");

        // Connect to the WMI namespace for DeviceGuard.
        let server = locator
            .ConnectServer(
                &BSTR::from("root\\Microsoft\\Windows\\DeviceGuard"),
                &BSTR::new(), // No username provided.
                &BSTR::new(), // No password provided.
                &BSTR::new(), // No locale specified.
                0,
                &BSTR::new(), // No authority specified.
                None,         // No additional context.
            )
            .expect("ConnectServer failed");

        // Execute a WQL query to select all properties from Win32_DeviceGuard.
        let query = server
            .ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from("SELECT * FROM Win32_DeviceGuard"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
            .expect("ExecQuery failed");
        let mut dg = DeviceGuard::default();

        // Retrieve and process the first available object from the query results.
        loop {
            let mut row: [Option<IWbemClassObject>; 1] = [None];
            let mut returned = 0;
            query
                .Next(WBEM_INFINITE, &mut row, &mut returned)
                .ok()
                .expect("Query Next failed");
            if let Some(object) = row[0].as_ref() {
                // Begin enumerating the properties of the retrieved object.
                object.BeginEnumeration(0).expect("BeginEnumeration failed");
                loop {
                    let mut prop_name: BSTR = BSTR::new();
                    let mut value = VARIANT::default();
                    let mut cim_type = 0;
                    let mut flavor = 0;

                    // Retrieve the next property; if there are none left, break the loop.
                    if object
                        .Next(0, &mut prop_name, &mut value, &mut cim_type, &mut flavor)
                        .is_err()
                    {
                        break;
                    }
                    if prop_name.is_empty() {
                        break;
                    }
                    let name = prop_name.to_string();

                    // Update the DeviceGuard struct with the current property.
                    dg.set_property(&name, &value);
                }

                // End enumeration of object properties.
                object.EndEnumeration().expect("EndEnumeration failed");
                break;
            } else {
                break;
            }
        }
        dg
    }
}

/// An extern "C" function to query DeviceGuard information and return it as a JSON string.
///
/// The JSON string is allocated on the heap, so the caller (C# consumer)
/// should use `free_json_string` to release the memory when done.
#[unsafe(no_mangle)]
pub extern "C" fn get_device_guard_json() -> *mut c_char {
    let json_result: String = std::panic::catch_unwind(|| {
        let dg: DeviceGuard = query_device_guard();
        serde_json::to_string(&dg)
            .unwrap_or_else(|e| format!("{{\"error\": \"JSON serialization failed: {}\"}}", e))
    })
    .map_err(|e| {
        format!("{{\"error\": \"A panic occurred: {:?}\"}}", e)
    })
    .unwrap_or_else(|err| err);

    let cstring = CString::new(json_result).expect("CString::new failed");
    cstring.into_raw()
}

/// Extern "C" function to free a JSON string that was allocated by `get_device_guard_json`.
#[unsafe(no_mangle)]
pub extern "C" fn free_json_string(s: *mut c_char) {
    // If the pointer is null, do nothing.
    if s.is_null() {
        return;
    }

    // Reconstruct the CString so that it is properly deallocated.
    unsafe {
        let _ = CString::from_raw(s);
    }
}

#![allow(non_snake_case)]

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

/// Converts a BSTR to an Option<String>.
/// Returns None if the string is empty, otherwise returns the string wrapped in Some.
fn bstr_to_option(bstr: &BSTR) -> Option<String> {
    let s = bstr.to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// A structure representing the properties retrieved from the Win32_DeviceGuard WMI class.
///
/// The field order mirrors the output order seen when printing the data.
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
    /// Decode a SAFEARRAY containing 16-bit integers (VT_ARRAY|VT_I2) to a vector of strings.
    ///
    /// Iterates over the array from lower bound to upper bound and converts each element into a string.
    /// Returns None if any step fails.
    unsafe fn decode_i16_array(parray: *mut SAFEARRAY) -> Option<Vec<String>> {
        // Retrieve the lower and upper bounds of the SAFEARRAY.
        let lbound = unsafe { SafeArrayGetLBound(parray, 1) }.ok()?;
        let ubound = unsafe { SafeArrayGetUBound(parray, 1) }.ok()?;
        let mut result = Vec::new();
        // Loop through each index within the bounds.
        for i in lbound..=ubound {
            let mut val: i16 = 0;
            let index: i32 = i; // Convert index to a 32-bit integer for the function call.
            unsafe {
                // Fetch the element from the SAFEARRAY.
                SafeArrayGetElement(parray, &index as *const i32, &mut val as *mut i16 as *mut _)
            }
            .ok()?;
            // Convert the integer to a string and append it to the result vector.
            result.push(val.to_string());
        }
        Some(result)
    }

    /// Updates the DeviceGuard struct with a property value based on the property's name
    /// and its corresponding VARIANT value.
    ///
    /// For string types (VT_BSTR), the helper `bstr_to_option` is used.
    /// For arrays of 16-bit integers (VT_ARRAY|VT_I2), the custom decoder `decode_i16_array` is employed.
    ///
    unsafe fn set_property(&mut self, name: &str, var: &VARIANT) {
        match name {
            // __PATH field: expects a BSTR type.
            "__PATH" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__PATH =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            // __NAMESPACE field: expects a BSTR type.
            "__NAMESPACE" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__NAMESPACE =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            // __SERVER field: expects a BSTR type.
            "__SERVER" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__SERVER =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            // __DERIVATION field: expects a specific BSTR type (value 8200).
            "__DERIVATION" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8200 {
                    self.__DERIVATION =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            // __PROPERTY_COUNT field: expects an integer.
            "__PROPERTY_COUNT" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.__PROPERTY_COUNT = Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            // __RELPATH field: expects a BSTR type.
            "__RELPATH" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__RELPATH =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            // __DYNASTY field: expects a BSTR type.
            "__DYNASTY" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__DYNASTY =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            // __SUPERCLASS field: if the type is 1, it is ignored (set as None).
            "__SUPERCLASS" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 1 {
                    self.__SUPERCLASS = None;
                }
            }
            // __CLASS field: expects a BSTR type.
            "__CLASS" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__CLASS =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            // __GENUS field: expects an integer.
            "__GENUS" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.__GENUS = Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            // AvailableSecurityProperties: handles arrays (VT_ARRAY|VT_I2).
            "AvailableSecurityProperties" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8195 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.AvailableSecurityProperties =
                            unsafe { DeviceGuard::decode_i16_array(parray) };
                    }
                }
            }
            // CodeIntegrityPolicyEnforcementStatus: expects an integer.
            "CodeIntegrityPolicyEnforcementStatus" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.CodeIntegrityPolicyEnforcementStatus =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            // InstanceIdentifier field: expects a BSTR type.
            "InstanceIdentifier" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.InstanceIdentifier =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            // RequiredSecurityProperties: handles both array type and single BSTR fallback.
            "RequiredSecurityProperties" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8195 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.RequiredSecurityProperties =
                            unsafe { DeviceGuard::decode_i16_array(parray) };
                    }
                } else {
                    self.RequiredSecurityProperties =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal })
                            .map(|s| vec![s]);
                }
            }
            // SecurityFeaturesEnabled: handles both array type and single BSTR fallback.
            "SecurityFeaturesEnabled" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8195 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.SecurityFeaturesEnabled =
                            unsafe { DeviceGuard::decode_i16_array(parray) };
                    }
                } else {
                    self.SecurityFeaturesEnabled =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal })
                            .map(|s| vec![s]);
                }
            }
            // SecurityServicesConfigured: handles both array type and single BSTR fallback.
            "SecurityServicesConfigured" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8195 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.SecurityServicesConfigured =
                            unsafe { DeviceGuard::decode_i16_array(parray) };
                    }
                } else {
                    self.SecurityServicesConfigured =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal })
                            .map(|s| vec![s]);
                }
            }
            // SecurityServicesRunning: handles both array type and single BSTR fallback.
            "SecurityServicesRunning" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8195 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.SecurityServicesRunning =
                            unsafe { DeviceGuard::decode_i16_array(parray) };
                    }
                } else {
                    self.SecurityServicesRunning =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal })
                            .map(|s| vec![s]);
                }
            }
            // SmmIsolationLevel: expects a byte (u8).
            "SmmIsolationLevel" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.SmmIsolationLevel =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            // UsermodeCodeIntegrityPolicyEnforcementStatus: expects an integer.
            "UsermodeCodeIntegrityPolicyEnforcementStatus" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.UsermodeCodeIntegrityPolicyEnforcementStatus =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            // Version field: expects a BSTR type.
            "Version" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.Version =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal });
                }
            }
            // VirtualizationBasedSecurityStatus: expects an integer.
            "VirtualizationBasedSecurityStatus" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.VirtualizationBasedSecurityStatus =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            // VirtualMachineIsolation: expects a boolean.
            "VirtualMachineIsolation" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.VirtualMachineIsolation =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            // VirtualMachineIsolationProperties: handles both array type and single BSTR fallback.
            "VirtualMachineIsolationProperties" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8195 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.VirtualMachineIsolationProperties =
                            unsafe { DeviceGuard::decode_i16_array(parray) };
                    }
                } else {
                    self.VirtualMachineIsolationProperties =
                        bstr_to_option(unsafe { &var.Anonymous.Anonymous.Anonymous.bstrVal })
                            .map(|s| vec![s]);
                }
            }
            // For any unrecognized property name, ignore it.
            _ => {}
        }
    }
}

/// Queries the WMI namespace "root\\Microsoft\\Windows\\DeviceGuard"
/// and returns the first found DeviceGuard instance.
///
/// This function sets up COM and connects to WMI, runs a WQL query,
/// and then iterates through the returned properties to populate the DeviceGuard struct.
fn query_device_guard() -> DeviceGuard {
    // Initialize COM with multi-threaded concurrency.
    unsafe {
        {
            CoInitializeEx(None, COINIT_MULTITHREADED)
                .ok()
                .expect("CoInitializeEx failed");
        }
        // Set COM security levels.
        {
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
        }
        // Create an instance of the WMI locator.
        let locator: IWbemLocator = {
            CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
                .expect("Failed to create IWbemLocator instance")
        };
        // Connect to the DeviceGuard WMI namespace.
        let server = {
            locator
                .ConnectServer(
                    &BSTR::from("root\\Microsoft\\Windows\\DeviceGuard"),
                    &BSTR::new(), // No username is provided.
                    &BSTR::new(), // No password is provided.
                    &BSTR::new(), // No locale specified.
                    0,
                    &BSTR::new(), // No authority specified.
                    None,         // No additional context.
                )
                .expect("ConnectServer failed")
        };

        // Execute the WMI query to retrieve all properties from Win32_DeviceGuard.
        let query = {
            server
                .ExecQuery(
                    &BSTR::from("WQL"),
                    &BSTR::from("SELECT * FROM Win32_DeviceGuard"),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    None,
                )
                .expect("ExecQuery failed")
        };
        let mut dg = DeviceGuard::default();

        // Process the first object returned from the query.
        loop {
            let mut row: [Option<IWbemClassObject>; 1] = [None];
            let mut returned = 0;
            {
                query
                    .Next(WBEM_INFINITE, &mut row, &mut returned)
                    .ok()
                    .expect("Query Next failed");
            }
            if let Some(object) = row[0].as_ref() {
                {
                    // Begin iterating through the object's properties.
                    object.BeginEnumeration(0).expect("BeginEnumeration failed");
                }
                loop {
                    let mut prop_name: BSTR = BSTR::new();
                    let mut value = VARIANT::default();
                    let mut cim_type = 0;
                    let mut flavor = 0;

                    // Retrieve the next property; break if none is found.
                    if { object.Next(0, &mut prop_name, &mut value, &mut cim_type, &mut flavor) }
                        .is_err()
                    {
                        break;
                    }
                    if prop_name.is_empty() {
                        break;
                    }
                    let name = prop_name.to_string();

                    // Use the helper to update the property in our DeviceGuard instance.
                    dg.set_property(&name, &value)
                }
                {
                    // End property enumeration.
                    object.EndEnumeration().expect("EndEnumeration failed");
                }
                break;
            } else {
                break;
            }
        }
        dg
    }
}

fn main() -> Result<()> {
    let dg = query_device_guard();
    let json_result = serde_json::to_string_pretty(&dg)
        .unwrap_or_else(|e| format!("{{\"error\": \"JSON serialization failed: {}\"}}", e));
    println!("{}", json_result);
    Ok(())
}

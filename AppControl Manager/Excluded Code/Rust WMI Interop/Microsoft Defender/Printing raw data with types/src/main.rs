use windows::{Win32::System::Com::*, Win32::System::Variant::*, Win32::System::Wmi::*, core::*};

fn main() -> Result<()> {
    unsafe {
        // Initialize COM in multi-threaded mode.
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;

        // Set up COM security.
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
        )?;

        // Create the WMI locator.
        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;

        // Connect to the namespace.
        let server = locator.ConnectServer(
            &BSTR::from("ROOT\\Microsoft\\Windows\\Defender"),
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            0,
            &BSTR::new(),
            None,
        )?;

        // Execute a query to select all properties from MSFT_MpPreference.
        let query = server.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from("SELECT * FROM MSFT_MpPreference"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )?;

        // Loop over each object returned by the query.
        loop {
            let mut row: [Option<IWbemClassObject>; 1] = [None];
            let mut returned = 0;
            query.Next(WBEM_INFINITE, &mut row, &mut returned).ok()?;

            if let Some(object) = row[0].as_ref() {
                // Begin enumeration of all properties.
                object.BeginEnumeration(0)?;
                loop {
                    // Prepare holders for property information.
                    let mut prop_name: BSTR = BSTR::new();
                    let mut value = VARIANT::default();
                    let mut cim_type = 0;
                    let mut flavor = 0;

                    // Attempt to retrieve the next property.
                    // When no more properties exist, either an error is returned or
                    // prop_name remains empty.
                    if object
                        .Next(0, &mut prop_name, &mut value, &mut cim_type, &mut flavor)
                        .is_err()
                    {
                        break;
                    }
                    if prop_name.is_empty() {
                        break;
                    }
                    // Print the property name and value.
                    println!("{}: {:?}", prop_name.to_string(), value);
                }
                object.EndEnumeration()?;
            } else {
                break;
            }
        }
        Ok(())
    }
}

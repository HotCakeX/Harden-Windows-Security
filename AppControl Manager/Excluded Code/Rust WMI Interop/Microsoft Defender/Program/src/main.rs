#![allow(non_snake_case)]

// Standard library imports.
use std::{mem::transmute, ptr::null_mut};

// Windows COM and WMI related imports.
use windows::{
    Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoInitializeSecurity, EOAC_NONE, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        SAFEARRAY,
    },
    Win32::System::Ole::{
        SafeArrayAccessData, SafeArrayGetLBound, SafeArrayGetUBound, SafeArrayUnaccessData,
    },
    Win32::System::Variant::*,
    Win32::System::Wmi::*,
    core::*,
};

/// Helper function to convert a BSTR (passed by reference) to an Option<String>.
/// If the BSTR converts to an empty string then returns None, otherwise Some(String).
fn bstr_to_option(bstr: &BSTR) -> Option<String> {
    let s = bstr.to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Returns a reference to the inner BSTR that is stored in the VARIANT's union field.
/// The dereference of the raw pointer is encapsulated in an unsafe block.
unsafe fn get_bstr_ref(var: &VARIANT) -> &BSTR {
    unsafe {
        let ptr = std::ptr::addr_of!(var.Anonymous.Anonymous.Anonymous.bstrVal);
        &*(ptr as *const BSTR)
    }
}

/// MpPreferences represents properties from the Defender WMI class.
/// Properties which return safe arrays are represented as vectors of strings.
#[derive(Debug, Default)]
struct MpPreferences {
    __PATH: Option<String>,
    __NAMESPACE: Option<String>,
    __SERVER: Option<String>,
    __DERIVATION: Option<String>,
    __PROPERTY_COUNT: Option<i32>,
    __RELPATH: Option<String>,
    __DYNASTY: Option<String>,
    __SUPERCLASS: Option<String>,
    __CLASS: Option<String>,
    __GENUS: Option<i32>,
    AllowDatagramProcessingOnWinServer: Option<bool>,
    AllowNetworkProtectionDownLevel: Option<bool>,
    AllowNetworkProtectionOnWinServer: Option<bool>,
    AllowSwitchToAsyncInspection: Option<bool>,
    ApplyDisableNetworkScanningToIOAV: Option<bool>,
    AttackSurfaceReductionOnlyExclusions: Option<Vec<String>>,
    AttackSurfaceReductionRules_Actions: Option<Vec<String>>,
    AttackSurfaceReductionRules_Ids: Option<Vec<String>>,
    AttackSurfaceReductionRules_RuleSpecificExclusions: Option<String>,
    AttackSurfaceReductionRules_RuleSpecificExclusions_Id: Option<String>,
    BruteForceProtectionAggressiveness: Option<u8>,
    BruteForceProtectionConfiguredState: Option<u8>,
    BruteForceProtectionExclusions: Option<String>,
    BruteForceProtectionLocalNetworkBlocking: Option<bool>,
    BruteForceProtectionMaxBlockTime: Option<i32>,
    BruteForceProtectionSkipLearningPeriod: Option<bool>,
    CheckForSignaturesBeforeRunningScan: Option<bool>,
    CloudBlockLevel: Option<u8>,
    CloudExtendedTimeout: Option<i32>,
    ComputerID: Option<String>,
    ControlledFolderAccessAllowedApplications: Option<Vec<String>>,
    ControlledFolderAccessDefaultProtectedFolders: Option<Vec<String>>,
    ControlledFolderAccessProtectedFolders: Option<Vec<String>>,
    DefinitionUpdatesChannel: Option<u8>,
    DisableArchiveScanning: Option<bool>,
    DisableAutoExclusions: Option<bool>,
    DisableBehaviorMonitoring: Option<bool>,
    DisableBlockAtFirstSeen: Option<bool>,
    DisableCacheMaintenance: Option<bool>,
    DisableCatchupFullScan: Option<bool>,
    DisableCatchupQuickScan: Option<bool>,
    DisableCoreServiceECSIntegration: Option<bool>,
    DisableCoreServiceTelemetry: Option<bool>,
    DisableCpuThrottleOnIdleScans: Option<bool>,
    DisableDatagramProcessing: Option<bool>,
    DisableDnsOverTcpParsing: Option<bool>,
    DisableDnsParsing: Option<bool>,
    DisableEmailScanning: Option<bool>,
    DisableFtpParsing: Option<bool>,
    DisableGradualRelease: Option<bool>,
    DisableHttpParsing: Option<bool>,
    DisableInboundConnectionFiltering: Option<bool>,
    DisableIOAVProtection: Option<bool>,
    DisableNetworkProtectionPerfTelemetry: Option<bool>,
    DisablePrivacyMode: Option<bool>,
    DisableQuicParsing: Option<bool>,
    DisableRdpParsing: Option<bool>,
    DisableRealtimeMonitoring: Option<bool>,
    DisableRemovableDriveScanning: Option<bool>,
    DisableRestorePoint: Option<bool>,
    DisableScanningMappedNetworkDrivesForFullScan: Option<bool>,
    DisableScanningNetworkFiles: Option<bool>,
    DisableScriptScanning: Option<bool>,
    DisableSmtpParsing: Option<bool>,
    DisableSshParsing: Option<bool>,
    DisableTamperProtection: Option<bool>,
    DisableTlsParsing: Option<bool>,
    EnableControlledFolderAccess: Option<u8>,
    EnableConvertWarnToBlock: Option<bool>,
    EnableDnsSinkhole: Option<bool>,
    EnableFileHashComputation: Option<bool>,
    EnableFullScanOnBatteryPower: Option<bool>,
    EnableLowCpuPriority: Option<bool>,
    EnableNetworkProtection: Option<u8>,
    EnableUdpReceiveOffload: Option<bool>,
    EnableUdpSegmentationOffload: Option<bool>,
    EngineUpdatesChannel: Option<u8>,
    ExclusionExtension: Option<String>,
    ExclusionIpAddress: Option<String>,
    ExclusionPath: Option<String>,
    ExclusionProcess: Option<String>,
    ForceUseProxyOnly: Option<bool>,
    HideExclusionsFromLocalUsers: Option<bool>,
    HighThreatDefaultAction: Option<u8>,
    IntelTDTEnabled: Option<bool>,
    LowThreatDefaultAction: Option<u8>,
    MAPSReporting: Option<u8>,
    MeteredConnectionUpdates: Option<bool>,
    ModerateThreatDefaultAction: Option<u8>,
    NetworkProtectionReputationMode: Option<i32>,
    OobeEnableRtpAndSigUpdate: Option<bool>,
    PerformanceModeStatus: Option<u8>,
    PlatformUpdatesChannel: Option<u8>,
    ProxyBypass: Option<String>,
    ProxyPacUrl: Option<String>,
    ProxyServer: Option<String>,
    PUAProtection: Option<u8>,
    QuarantinePurgeItemsAfterDelay: Option<i32>,
    QuickScanIncludeExclusions: Option<u8>,
    RandomizeScheduleTaskTimes: Option<bool>,
    RealTimeScanDirection: Option<u8>,
    RemediationScheduleDay: Option<u8>,
    RemediationScheduleTime: Option<String>,
    RemoteEncryptionProtectionAggressiveness: Option<u8>,
    RemoteEncryptionProtectionConfiguredState: Option<u8>,
    RemoteEncryptionProtectionExclusions: Option<Vec<String>>,
    RemoteEncryptionProtectionMaxBlockTime: Option<i32>,
    RemoveScanningThreadPoolCap: Option<bool>,
    ReportDynamicSignatureDroppedEvent: Option<bool>,
    ReportingAdditionalActionTimeOut: Option<i32>,
    ReportingCriticalFailureTimeOut: Option<i32>,
    ReportingNonCriticalTimeOut: Option<i32>,
    ScanAvgCPULoadFactor: Option<u8>,
    ScanOnlyIfIdleEnabled: Option<bool>,
    ScanParameters: Option<u8>,
    ScanPurgeItemsAfterDelay: Option<i32>,
    ScanScheduleDay: Option<u8>,
    ScanScheduleOffset: Option<i32>,
    ScanScheduleQuickScanTime: Option<String>,
    ScanScheduleTime: Option<String>,
    SchedulerRandomizationTime: Option<i32>,
    ServiceHealthReportInterval: Option<i32>,
    SevereThreatDefaultAction: Option<u8>,
    SharedSignaturesPath: Option<String>,
    SharedSignaturesPathUpdateAtScheduledTimeOnly: Option<bool>,
    SignatureAuGracePeriod: Option<i32>,
    SignatureBlobFileSharesSources: Option<String>,
    SignatureBlobUpdateInterval: Option<i32>,
    SignatureDefinitionUpdateFileSharesSources: Option<String>,
    SignatureDisableUpdateOnStartupWithoutEngine: Option<bool>,
    SignatureFallbackOrder: Option<String>,
    SignatureFirstAuGracePeriod: Option<i32>,
    SignatureScheduleDay: Option<u8>,
    SignatureScheduleTime: Option<String>,
    SignatureUpdateCatchupInterval: Option<i32>,
    SignatureUpdateInterval: Option<i32>,
    SubmitSamplesConsent: Option<u8>,
    ThreatIDDefaultAction_Actions: Option<Vec<String>>,
    ThreatIDDefaultAction_Ids: Option<Vec<String>>,
    ThrottleForScheduledScanOnly: Option<bool>,
    TrustLabelProtectionStatus: Option<i32>,
    UILockdown: Option<bool>,
    UnknownThreatDefaultAction: Option<u8>,
}

impl MpPreferences {
    /// Helper to decode a SAFEARRAY of BSTR items into a Vec<String>.
    /// This function retrieves the lower and upper bounds of the array, then accesses the data,
    /// and converts each BSTR to a string. Always unaccesses the safe array after processing.
    unsafe fn decode_bstr_array(parray: *mut SAFEARRAY) -> Option<Vec<String>> {
        let lbound = unsafe { SafeArrayGetLBound(parray, 1) }.ok()?;
        let ubound = unsafe { SafeArrayGetUBound(parray, 1) }.ok()?;
        let count = ubound - lbound + 1;
        let mut result = Vec::with_capacity(count as usize);
        let mut data_ptr: *mut BSTR = null_mut();
        if unsafe { SafeArrayAccessData(parray, transmute(&mut data_ptr)) }.is_err() {
            return None;
        }
        for i in 0..count {
            // Clone each BSTR to avoid moving from a raw pointer.
            let bstr = unsafe { (*data_ptr.offset(i as isize)).clone() };
            result.push(bstr.to_string());
        }
        // Always unaccess the array to release the lock.
        let _ = unsafe { SafeArrayUnaccessData(parray) };
        Some(result)
    }

    /// Helper to decode a SAFEARRAY of u8 items into a Vec<String>.
    /// This function is similar to `decode_bstr_array` but handles elements as u8.
    unsafe fn decode_u8_array(parray: *mut SAFEARRAY) -> Option<Vec<String>> {
        let lbound = unsafe { SafeArrayGetLBound(parray, 1) }.ok()?;
        let ubound = unsafe { SafeArrayGetUBound(parray, 1) }.ok()?;
        let count = ubound - lbound + 1;
        let mut result = Vec::with_capacity(count as usize);
        let mut data_ptr: *mut u8 = null_mut();
        if unsafe { SafeArrayAccessData(parray, transmute(&mut data_ptr)) }.is_err() {
            return None;
        }
        for i in 0..count {
            let value = unsafe { *data_ptr.offset(i as isize) };
            result.push(value.to_string());
        }
        // Always unaccess the safe array after processing.
        let _ = unsafe { SafeArrayUnaccessData(parray) };
        Some(result)
    }

    /// Given a property name and its associated VARIANT value from WMI,
    /// this helper function assigns the value to the corresponding field of the MpPreferences struct.
    /// additional cases should be added here when new parameters are available for the Defender MpPreferences.
    unsafe fn set_property(&mut self, name: &str, var: &VARIANT) {
        match name {
            // Conversion of BSTR properties.
            "ExclusionPath" => {
                self.ExclusionPath = bstr_to_option(unsafe { get_bstr_ref(var) });
            }
            "ExclusionProcess" => {
                self.ExclusionProcess = bstr_to_option(unsafe { get_bstr_ref(var) });
            }
            // Boolean values stored in VARIANT with vt == 11.
            "ForceUseProxyOnly" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.ForceUseProxyOnly =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "HideExclusionsFromLocalUsers" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.HideExclusionsFromLocalUsers =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            // Byte values stored in VARIANT with vt == 17.
            "HighThreatDefaultAction" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.HighThreatDefaultAction =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "IntelTDTEnabled" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.IntelTDTEnabled =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "LowThreatDefaultAction" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.LowThreatDefaultAction =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "MAPSReporting" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.MAPSReporting = Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "MeteredConnectionUpdates" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.MeteredConnectionUpdates =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "ModerateThreatDefaultAction" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.ModerateThreatDefaultAction =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "NetworkProtectionReputationMode" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.NetworkProtectionReputationMode =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "OobeEnableRtpAndSigUpdate" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.OobeEnableRtpAndSigUpdate =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "PerformanceModeStatus" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.PerformanceModeStatus =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "PlatformUpdatesChannel" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.PlatformUpdatesChannel =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "ProxyBypass" => {
                self.ProxyBypass = bstr_to_option(unsafe { get_bstr_ref(var) });
            }
            "ProxyPacUrl" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.ProxyPacUrl = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "ProxyServer" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.ProxyServer = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "PUAProtection" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.PUAProtection = Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "QuarantinePurgeItemsAfterDelay" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.QuarantinePurgeItemsAfterDelay =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "QuickScanIncludeExclusions" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.QuickScanIncludeExclusions =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "RandomizeScheduleTaskTimes" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.RandomizeScheduleTaskTimes =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "RealTimeScanDirection" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.RealTimeScanDirection =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "RemediationScheduleDay" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.RemediationScheduleDay =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "RemediationScheduleTime" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.RemediationScheduleTime = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "RemoteEncryptionProtectionAggressiveness" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.RemoteEncryptionProtectionAggressiveness =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "RemoteEncryptionProtectionConfiguredState" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.RemoteEncryptionProtectionConfiguredState =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "RemoteEncryptionProtectionExclusions" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8200 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.RemoteEncryptionProtectionExclusions =
                            unsafe { MpPreferences::decode_bstr_array(parray) };
                    }
                } else {
                    self.RemoteEncryptionProtectionExclusions =
                        bstr_to_option(unsafe { get_bstr_ref(var) }).map(|s| vec![s]);
                }
            }
            "RemoteEncryptionProtectionMaxBlockTime" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.RemoteEncryptionProtectionMaxBlockTime =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "RemoveScanningThreadPoolCap" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.RemoveScanningThreadPoolCap =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "ReportDynamicSignatureDroppedEvent" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.ReportDynamicSignatureDroppedEvent =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "ReportingAdditionalActionTimeOut" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.ReportingAdditionalActionTimeOut =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "ReportingCriticalFailureTimeOut" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.ReportingCriticalFailureTimeOut =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "ReportingNonCriticalTimeOut" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.ReportingNonCriticalTimeOut =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "ScanAvgCPULoadFactor" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.ScanAvgCPULoadFactor =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "ScanOnlyIfIdleEnabled" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.ScanOnlyIfIdleEnabled =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "ScanParameters" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.ScanParameters = Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "ScanPurgeItemsAfterDelay" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.ScanPurgeItemsAfterDelay =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "ScanScheduleDay" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.ScanScheduleDay = Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "ScanScheduleOffset" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.ScanScheduleOffset =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "ScanScheduleQuickScanTime" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.ScanScheduleQuickScanTime = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "ScanScheduleTime" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.ScanScheduleTime = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "SchedulerRandomizationTime" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.SchedulerRandomizationTime =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "ServiceHealthReportInterval" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.ServiceHealthReportInterval =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "SevereThreatDefaultAction" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.SevereThreatDefaultAction =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "SharedSignaturesPath" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.SharedSignaturesPath = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "SharedSignaturesPathUpdateAtScheduledTimeOnly" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.SharedSignaturesPathUpdateAtScheduledTimeOnly =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "SignatureAuGracePeriod" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.SignatureAuGracePeriod =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "SignatureBlobFileSharesSources" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.SignatureBlobFileSharesSources =
                        bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "SignatureBlobUpdateInterval" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.SignatureBlobUpdateInterval =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "SignatureDefinitionUpdateFileSharesSources" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.SignatureDefinitionUpdateFileSharesSources =
                        bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "SignatureDisableUpdateOnStartupWithoutEngine" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.SignatureDisableUpdateOnStartupWithoutEngine =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "SignatureFallbackOrder" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.SignatureFallbackOrder = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "SignatureFirstAuGracePeriod" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.SignatureFirstAuGracePeriod =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "SignatureScheduleDay" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.SignatureScheduleDay =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "SignatureScheduleTime" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.SignatureScheduleTime = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "SignatureUpdateCatchupInterval" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.SignatureUpdateCatchupInterval =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "SignatureUpdateInterval" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.SignatureUpdateInterval =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "SubmitSamplesConsent" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.SubmitSamplesConsent =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "ThreatIDDefaultAction_Actions" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8209 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.ThreatIDDefaultAction_Actions =
                            unsafe { MpPreferences::decode_u8_array(parray) };
                    }
                }
            }
            "ThreatIDDefaultAction_Ids" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8200 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.ThreatIDDefaultAction_Ids =
                            unsafe { MpPreferences::decode_bstr_array(parray) };
                    }
                } else {
                    self.ThreatIDDefaultAction_Ids =
                        bstr_to_option(unsafe { get_bstr_ref(var) }).map(|s| vec![s]);
                }
            }
            "ThrottleForScheduledScanOnly" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.ThrottleForScheduledScanOnly =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "TrustLabelProtectionStatus" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.TrustLabelProtectionStatus =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "UILockdown" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.UILockdown =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "UnknownThreatDefaultAction" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.UnknownThreatDefaultAction =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "__PATH" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__PATH = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "__NAMESPACE" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__NAMESPACE = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "__SERVER" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__SERVER = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "__DERIVATION" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8200 {
                    self.__DERIVATION = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "__PROPERTY_COUNT" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.__PROPERTY_COUNT = Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "__RELPATH" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__RELPATH = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "__DYNASTY" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__DYNASTY = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "__SUPERCLASS" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 1 {
                    self.__SUPERCLASS = None;
                }
            }
            "__CLASS" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.__CLASS = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "__GENUS" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.__GENUS = Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            // Additional Defender WMI properties.
            "AllowDatagramProcessingOnWinServer" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.AllowDatagramProcessingOnWinServer =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "AllowNetworkProtectionDownLevel" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.AllowNetworkProtectionDownLevel =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "AllowNetworkProtectionOnWinServer" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.AllowNetworkProtectionOnWinServer =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "AllowSwitchToAsyncInspection" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.AllowSwitchToAsyncInspection =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "ApplyDisableNetworkScanningToIOAV" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.ApplyDisableNetworkScanningToIOAV =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "AttackSurfaceReductionOnlyExclusions" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8200 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.AttackSurfaceReductionOnlyExclusions =
                            unsafe { MpPreferences::decode_bstr_array(parray) };
                    }
                } else {
                    self.AttackSurfaceReductionOnlyExclusions =
                        bstr_to_option(unsafe { get_bstr_ref(var) }).map(|s| vec![s]);
                }
            }
            "AttackSurfaceReductionRules_Actions" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8209 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.AttackSurfaceReductionRules_Actions =
                            unsafe { MpPreferences::decode_u8_array(parray) };
                    }
                } else {
                    self.AttackSurfaceReductionRules_Actions = None;
                }
            }
            "AttackSurfaceReductionRules_Ids" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8200 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.AttackSurfaceReductionRules_Ids =
                            unsafe { MpPreferences::decode_bstr_array(parray) };
                    }
                } else {
                    self.AttackSurfaceReductionRules_Ids =
                        bstr_to_option(unsafe { get_bstr_ref(var) }).map(|s| vec![s]);
                }
            }
            "AttackSurfaceReductionRules_RuleSpecificExclusions" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 1 {
                    self.AttackSurfaceReductionRules_RuleSpecificExclusions = None;
                } else {
                    self.AttackSurfaceReductionRules_RuleSpecificExclusions =
                        bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "AttackSurfaceReductionRules_RuleSpecificExclusions_Id" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 1 {
                    self.AttackSurfaceReductionRules_RuleSpecificExclusions_Id = None;
                } else {
                    self.AttackSurfaceReductionRules_RuleSpecificExclusions_Id =
                        bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "BruteForceProtectionAggressiveness" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.BruteForceProtectionAggressiveness =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "BruteForceProtectionConfiguredState" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.BruteForceProtectionConfiguredState =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "BruteForceProtectionExclusions" => {
                self.BruteForceProtectionExclusions = bstr_to_option(unsafe { get_bstr_ref(var) });
            }
            "BruteForceProtectionLocalNetworkBlocking" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.BruteForceProtectionLocalNetworkBlocking =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "BruteForceProtectionMaxBlockTime" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.BruteForceProtectionMaxBlockTime =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "BruteForceProtectionSkipLearningPeriod" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.BruteForceProtectionSkipLearningPeriod =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "CheckForSignaturesBeforeRunningScan" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.CheckForSignaturesBeforeRunningScan =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "CloudBlockLevel" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.CloudBlockLevel = Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "CloudExtendedTimeout" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 3 {
                    self.CloudExtendedTimeout =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.lVal });
                }
            }
            "ComputerID" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8 {
                    self.ComputerID = bstr_to_option(unsafe { get_bstr_ref(var) });
                }
            }
            "ControlledFolderAccessAllowedApplications" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8200 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.ControlledFolderAccessAllowedApplications =
                            unsafe { MpPreferences::decode_bstr_array(parray) };
                    }
                } else {
                    self.ControlledFolderAccessAllowedApplications =
                        bstr_to_option(unsafe { get_bstr_ref(var) }).map(|s| vec![s]);
                }
            }
            "ControlledFolderAccessDefaultProtectedFolders" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8200 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.ControlledFolderAccessDefaultProtectedFolders =
                            unsafe { MpPreferences::decode_bstr_array(parray) };
                    }
                } else {
                    self.ControlledFolderAccessDefaultProtectedFolders =
                        bstr_to_option(unsafe { get_bstr_ref(var) }).map(|s| vec![s]);
                }
            }
            "ControlledFolderAccessProtectedFolders" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 8200 {
                    let parray = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
                    if !parray.is_null() {
                        self.ControlledFolderAccessProtectedFolders =
                            unsafe { MpPreferences::decode_bstr_array(parray) };
                    }
                } else {
                    self.ControlledFolderAccessProtectedFolders =
                        bstr_to_option(unsafe { get_bstr_ref(var) }).map(|s| vec![s]);
                }
            }
            "DefinitionUpdatesChannel" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.DefinitionUpdatesChannel =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "DisableArchiveScanning" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableArchiveScanning =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableAutoExclusions" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableAutoExclusions =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableBehaviorMonitoring" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableBehaviorMonitoring =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableBlockAtFirstSeen" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableBlockAtFirstSeen =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableCacheMaintenance" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableCacheMaintenance =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableCatchupFullScan" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableCatchupFullScan =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableCatchupQuickScan" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableCatchupQuickScan =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableCoreServiceECSIntegration" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableCoreServiceECSIntegration =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableCoreServiceTelemetry" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableCoreServiceTelemetry =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableCpuThrottleOnIdleScans" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableCpuThrottleOnIdleScans =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableDatagramProcessing" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableDatagramProcessing =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableDnsOverTcpParsing" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableDnsOverTcpParsing =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableDnsParsing" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableDnsParsing =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableEmailScanning" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableEmailScanning =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableFtpParsing" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableFtpParsing =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableGradualRelease" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableGradualRelease =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableHttpParsing" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableHttpParsing =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableInboundConnectionFiltering" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableInboundConnectionFiltering =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableIOAVProtection" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableIOAVProtection =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableNetworkProtectionPerfTelemetry" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableNetworkProtectionPerfTelemetry =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisablePrivacyMode" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisablePrivacyMode =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableQuicParsing" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableQuicParsing =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableRdpParsing" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableRdpParsing =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableRealtimeMonitoring" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableRealtimeMonitoring =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableRemovableDriveScanning" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableRemovableDriveScanning =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableRestorePoint" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableRestorePoint =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableScanningMappedNetworkDrivesForFullScan" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableScanningMappedNetworkDrivesForFullScan =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableScanningNetworkFiles" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableScanningNetworkFiles =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableScriptScanning" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableScriptScanning =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableSmtpParsing" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableSmtpParsing =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableSshParsing" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableSshParsing =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableTamperProtection" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableTamperProtection =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "DisableTlsParsing" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.DisableTlsParsing =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "EnableControlledFolderAccess" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.EnableControlledFolderAccess =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "EnableConvertWarnToBlock" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.EnableConvertWarnToBlock =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "EnableDnsSinkhole" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.EnableDnsSinkhole =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "EnableFileHashComputation" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.EnableFileHashComputation =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "EnableFullScanOnBatteryPower" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.EnableFullScanOnBatteryPower =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "EnableLowCpuPriority" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.EnableLowCpuPriority =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "EnableNetworkProtection" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.EnableNetworkProtection =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "EnableUdpReceiveOffload" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.EnableUdpReceiveOffload =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "EnableUdpSegmentationOffload" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 11 {
                    self.EnableUdpSegmentationOffload =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.boolVal }.into());
                }
            }
            "EngineUpdatesChannel" => {
                if unsafe { var.Anonymous.Anonymous.vt.0 } == 17 {
                    self.EngineUpdatesChannel =
                        Some(unsafe { var.Anonymous.Anonymous.Anonymous.bVal });
                }
            }
            "ExclusionExtension" => {
                self.ExclusionExtension = bstr_to_option(unsafe { get_bstr_ref(var) });
            }
            "ExclusionIpAddress" => {
                self.ExclusionIpAddress = bstr_to_option(unsafe { get_bstr_ref(var) });
            }
            _ => {}
        }
    }
}

fn main() -> Result<()> {
    unsafe {
        // Initialize COM in multithreaded mode required to use COM-based APIs.
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;

        // Set up COM security with default authentication and impersonation levels.
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

        // Create the WbemLocator COM object which is used to connect to the WMI service.
        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;

        // Connect to the Defender WMI namespace.
        let root = BSTR::from("ROOT\\Microsoft\\Windows\\Defender");

        // Create empty BSTRs for Username, Password, Locale, and Authority.
        // These are needed for ConnectServer, even if no values are provided.
        let username = BSTR::new();
        let password = BSTR::new();
        let locale = BSTR::new();
        let authority = BSTR::new();

        // Establish the connection to the Defender namespace.
        let server = locator.ConnectServer(
            &root, &username,  // Username
            &password,  // Password
            &locale,    // Locale
            0,          // Security flags
            &authority, // Authority
            None,       // Context
        )?;

        // Prepare and execute a WQL query to retrieve all properties from the MSFT_MpPreference class.
        let query_language = BSTR::from("WQL");
        let query_expr = BSTR::from("SELECT * FROM MSFT_MpPreference");
        let query = server.ExecQuery(
            &query_language,
            &query_expr,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )?;

        // Create an instance of MpPreferences to store the query results.
        let mut prefs = MpPreferences::default();

        // Process the first returned WMI object.
        loop {
            // Prepare a container for the result (an array with one optional IWbemClassObject).
            let mut row: [Option<IWbemClassObject>; 1] = [None];
            let mut returned = 0;

            query.Next(WBEM_INFINITE, &mut row, &mut returned).ok()?;
            if let Some(object) = row[0].as_ref() {
                // Begin iterating over the object's properties.
                object.BeginEnumeration(0)?;
                loop {
                    // Retrieve the next property name, its value, and additional type info.
                    let mut prop_name: BSTR = BSTR::new();
                    let mut value = VARIANT::default();
                    let mut cim_type = 0;
                    let mut flavor = 0;
                    if object
                        .Next(0, &mut prop_name, &mut value, &mut cim_type, &mut flavor)
                        .is_err()
                    {
                        break;
                    }
                    // If the property name is empty, we have finished enumerating.
                    if prop_name.is_empty() {
                        break;
                    }

                    // Convert the BSTR property name to a Rust String.
                    let name = prop_name.to_string();

                    // Set the corresponding field in the MpPreferences struct.
                    prefs.set_property(&name, &value);
                }

                // Complete the property enumeration.
                object.EndEnumeration()?;

                // We've processed the first result; break out of the loop.
                break;
            } else {
                // No object was returned; exit the loop.
                break;
            }
        }

        // Print the populated MpPreferences struct for debugging purposes.
        println!("{:#?}", prefs);
        Ok(())
    }
}

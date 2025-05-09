using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RustInterop;

internal sealed class MpPreferences
{
    [JsonInclude]
    [JsonPropertyOrder(0)]
    [JsonPropertyName("__PATH")]
    internal string? __PATH { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(1)]
    [JsonPropertyName("__NAMESPACE")]
    internal string? __NAMESPACE { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(2)]
    [JsonPropertyName("__SERVER")]
    internal string? __SERVER { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(3)]
    [JsonPropertyName("__DERIVATION")]
    internal string? __DERIVATION { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(4)]
    [JsonPropertyName("__PROPERTY_COUNT")]
    internal int? __PROPERTY_COUNT { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(5)]
    [JsonPropertyName("__RELPATH")]
    internal string? __RELPATH { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(6)]
    [JsonPropertyName("__DYNASTY")]
    internal string? __DYNASTY { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(7)]
    [JsonPropertyName("__SUPERCLASS")]
    internal string? __SUPERCLASS { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(8)]
    [JsonPropertyName("__CLASS")]
    internal string? __CLASS { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(9)]
    [JsonPropertyName("__GENUS")]
    internal int? __GENUS { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(10)]
    [JsonPropertyName("AllowDatagramProcessingOnWinServer")]
    internal bool? AllowDatagramProcessingOnWinServer { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(11)]
    [JsonPropertyName("AllowNetworkProtectionDownLevel")]
    internal bool? AllowNetworkProtectionDownLevel { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(12)]
    [JsonPropertyName("AllowNetworkProtectionOnWinServer")]
    internal bool? AllowNetworkProtectionOnWinServer { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(13)]
    [JsonPropertyName("AllowSwitchToAsyncInspection")]
    internal bool? AllowSwitchToAsyncInspection { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(14)]
    [JsonPropertyName("ApplyDisableNetworkScanningToIOAV")]
    internal bool? ApplyDisableNetworkScanningToIOAV { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(15)]
    [JsonPropertyName("AttackSurfaceReductionOnlyExclusions")]
    internal List<string>? AttackSurfaceReductionOnlyExclusions { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(16)]
    [JsonPropertyName("AttackSurfaceReductionRules_Actions")]
    internal List<string>? AttackSurfaceReductionRules_Actions { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(17)]
    [JsonPropertyName("AttackSurfaceReductionRules_Ids")]
    internal List<string>? AttackSurfaceReductionRules_Ids { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(18)]
    [JsonPropertyName("AttackSurfaceReductionRules_RuleSpecificExclusions")]
    internal string? AttackSurfaceReductionRules_RuleSpecificExclusions { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(19)]
    [JsonPropertyName("AttackSurfaceReductionRules_RuleSpecificExclusions_Id")]
    internal string? AttackSurfaceReductionRules_RuleSpecificExclusions_Id { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(20)]
    [JsonPropertyName("BruteForceProtectionAggressiveness")]
    internal byte? BruteForceProtectionAggressiveness { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(21)]
    [JsonPropertyName("BruteForceProtectionConfiguredState")]
    internal byte? BruteForceProtectionConfiguredState { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(22)]
    [JsonPropertyName("BruteForceProtectionExclusions")]
    internal string? BruteForceProtectionExclusions { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(23)]
    [JsonPropertyName("BruteForceProtectionLocalNetworkBlocking")]
    internal bool? BruteForceProtectionLocalNetworkBlocking { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(24)]
    [JsonPropertyName("BruteForceProtectionMaxBlockTime")]
    internal int? BruteForceProtectionMaxBlockTime { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(25)]
    [JsonPropertyName("BruteForceProtectionSkipLearningPeriod")]
    internal bool? BruteForceProtectionSkipLearningPeriod { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(26)]
    [JsonPropertyName("CheckForSignaturesBeforeRunningScan")]
    internal bool? CheckForSignaturesBeforeRunningScan { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(27)]
    [JsonPropertyName("CloudBlockLevel")]
    internal byte? CloudBlockLevel { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(28)]
    [JsonPropertyName("CloudExtendedTimeout")]
    internal int? CloudExtendedTimeout { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(29)]
    [JsonPropertyName("ComputerID")]
    internal string? ComputerID { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(30)]
    [JsonPropertyName("ControlledFolderAccessAllowedApplications")]
    internal List<string>? ControlledFolderAccessAllowedApplications { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(31)]
    [JsonPropertyName("ControlledFolderAccessDefaultProtectedFolders")]
    internal List<string>? ControlledFolderAccessDefaultProtectedFolders { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(32)]
    [JsonPropertyName("ControlledFolderAccessProtectedFolders")]
    internal List<string>? ControlledFolderAccessProtectedFolders { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(33)]
    [JsonPropertyName("DefinitionUpdatesChannel")]
    internal byte? DefinitionUpdatesChannel { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(34)]
    [JsonPropertyName("DisableArchiveScanning")]
    internal bool? DisableArchiveScanning { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(35)]
    [JsonPropertyName("DisableAutoExclusions")]
    internal bool? DisableAutoExclusions { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(36)]
    [JsonPropertyName("DisableBehaviorMonitoring")]
    internal bool? DisableBehaviorMonitoring { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(37)]
    [JsonPropertyName("DisableBlockAtFirstSeen")]
    internal bool? DisableBlockAtFirstSeen { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(38)]
    [JsonPropertyName("DisableCacheMaintenance")]
    internal bool? DisableCacheMaintenance { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(39)]
    [JsonPropertyName("DisableCatchupFullScan")]
    internal bool? DisableCatchupFullScan { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(40)]
    [JsonPropertyName("DisableCatchupQuickScan")]
    internal bool? DisableCatchupQuickScan { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(41)]
    [JsonPropertyName("DisableCoreServiceECSIntegration")]
    internal bool? DisableCoreServiceECSIntegration { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(42)]
    [JsonPropertyName("DisableCoreServiceTelemetry")]
    internal bool? DisableCoreServiceTelemetry { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(43)]
    [JsonPropertyName("DisableCpuThrottleOnIdleScans")]
    internal bool? DisableCpuThrottleOnIdleScans { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(44)]
    [JsonPropertyName("DisableDatagramProcessing")]
    internal bool? DisableDatagramProcessing { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(45)]
    [JsonPropertyName("DisableDnsOverTcpParsing")]
    internal bool? DisableDnsOverTcpParsing { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(46)]
    [JsonPropertyName("DisableDnsParsing")]
    internal bool? DisableDnsParsing { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(47)]
    [JsonPropertyName("DisableEmailScanning")]
    internal bool? DisableEmailScanning { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(48)]
    [JsonPropertyName("DisableFtpParsing")]
    internal bool? DisableFtpParsing { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(49)]
    [JsonPropertyName("DisableGradualRelease")]
    internal bool? DisableGradualRelease { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(50)]
    [JsonPropertyName("DisableHttpParsing")]
    internal bool? DisableHttpParsing { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(51)]
    [JsonPropertyName("DisableInboundConnectionFiltering")]
    internal bool? DisableInboundConnectionFiltering { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(52)]
    [JsonPropertyName("DisableIOAVProtection")]
    internal bool? DisableIOAVProtection { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(53)]
    [JsonPropertyName("DisableNetworkProtectionPerfTelemetry")]
    internal bool? DisableNetworkProtectionPerfTelemetry { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(54)]
    [JsonPropertyName("DisablePrivacyMode")]
    internal bool? DisablePrivacyMode { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(55)]
    [JsonPropertyName("DisableQuicParsing")]
    internal bool? DisableQuicParsing { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(56)]
    [JsonPropertyName("DisableRdpParsing")]
    internal bool? DisableRdpParsing { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(57)]
    [JsonPropertyName("DisableRealtimeMonitoring")]
    internal bool? DisableRealtimeMonitoring { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(58)]
    [JsonPropertyName("DisableRemovableDriveScanning")]
    internal bool? DisableRemovableDriveScanning { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(59)]
    [JsonPropertyName("DisableRestorePoint")]
    internal bool? DisableRestorePoint { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(60)]
    [JsonPropertyName("DisableScanningMappedNetworkDrivesForFullScan")]
    internal bool? DisableScanningMappedNetworkDrivesForFullScan { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(61)]
    [JsonPropertyName("DisableScanningNetworkFiles")]
    internal bool? DisableScanningNetworkFiles { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(62)]
    [JsonPropertyName("DisableScriptScanning")]
    internal bool? DisableScriptScanning { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(63)]
    [JsonPropertyName("DisableSmtpParsing")]
    internal bool? DisableSmtpParsing { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(64)]
    [JsonPropertyName("DisableSshParsing")]
    internal bool? DisableSshParsing { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(65)]
    [JsonPropertyName("DisableTamperProtection")]
    internal bool? DisableTamperProtection { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(66)]
    [JsonPropertyName("DisableTlsParsing")]
    internal bool? DisableTlsParsing { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(67)]
    [JsonPropertyName("EnableControlledFolderAccess")]
    internal byte? EnableControlledFolderAccess { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(68)]
    [JsonPropertyName("EnableConvertWarnToBlock")]
    internal bool? EnableConvertWarnToBlock { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(69)]
    [JsonPropertyName("EnableDnsSinkhole")]
    internal bool? EnableDnsSinkhole { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(70)]
    [JsonPropertyName("EnableFileHashComputation")]
    internal bool? EnableFileHashComputation { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(71)]
    [JsonPropertyName("EnableFullScanOnBatteryPower")]
    internal bool? EnableFullScanOnBatteryPower { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(72)]
    [JsonPropertyName("EnableLowCpuPriority")]
    internal bool? EnableLowCpuPriority { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(73)]
    [JsonPropertyName("EnableNetworkProtection")]
    internal byte? EnableNetworkProtection { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(74)]
    [JsonPropertyName("EnableUdpReceiveOffload")]
    internal bool? EnableUdpReceiveOffload { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(75)]
    [JsonPropertyName("EnableUdpSegmentationOffload")]
    internal bool? EnableUdpSegmentationOffload { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(76)]
    [JsonPropertyName("EngineUpdatesChannel")]
    internal byte? EngineUpdatesChannel { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(77)]
    [JsonPropertyName("ExclusionExtension")]
    internal string? ExclusionExtension { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(78)]
    [JsonPropertyName("ExclusionIpAddress")]
    internal string? ExclusionIpAddress { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(79)]
    [JsonPropertyName("ExclusionPath")]
    internal string? ExclusionPath { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(80)]
    [JsonPropertyName("ExclusionProcess")]
    internal string? ExclusionProcess { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(81)]
    [JsonPropertyName("ForceUseProxyOnly")]
    internal bool? ForceUseProxyOnly { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(82)]
    [JsonPropertyName("HideExclusionsFromLocalUsers")]
    internal bool? HideExclusionsFromLocalUsers { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(83)]
    [JsonPropertyName("HighThreatDefaultAction")]
    internal byte? HighThreatDefaultAction { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(84)]
    [JsonPropertyName("IntelTDTEnabled")]
    internal bool? IntelTDTEnabled { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(85)]
    [JsonPropertyName("LowThreatDefaultAction")]
    internal byte? LowThreatDefaultAction { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(86)]
    [JsonPropertyName("MAPSReporting")]
    internal byte? MAPSReporting { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(87)]
    [JsonPropertyName("MeteredConnectionUpdates")]
    internal bool? MeteredConnectionUpdates { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(88)]
    [JsonPropertyName("ModerateThreatDefaultAction")]
    internal byte? ModerateThreatDefaultAction { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(89)]
    [JsonPropertyName("NetworkProtectionReputationMode")]
    internal int? NetworkProtectionReputationMode { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(90)]
    [JsonPropertyName("OobeEnableRtpAndSigUpdate")]
    internal bool? OobeEnableRtpAndSigUpdate { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(91)]
    [JsonPropertyName("PerformanceModeStatus")]
    internal byte? PerformanceModeStatus { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(92)]
    [JsonPropertyName("PlatformUpdatesChannel")]
    internal byte? PlatformUpdatesChannel { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(93)]
    [JsonPropertyName("ProxyBypass")]
    internal string? ProxyBypass { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(94)]
    [JsonPropertyName("ProxyPacUrl")]
    internal string? ProxyPacUrl { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(95)]
    [JsonPropertyName("ProxyServer")]
    internal string? ProxyServer { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(96)]
    [JsonPropertyName("PUAProtection")]
    internal byte? PUAProtection { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(97)]
    [JsonPropertyName("QuarantinePurgeItemsAfterDelay")]
    internal int? QuarantinePurgeItemsAfterDelay { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(98)]
    [JsonPropertyName("QuickScanIncludeExclusions")]
    internal byte? QuickScanIncludeExclusions { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(99)]
    [JsonPropertyName("RandomizeScheduleTaskTimes")]
    internal bool? RandomizeScheduleTaskTimes { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(100)]
    [JsonPropertyName("RealTimeScanDirection")]
    internal byte? RealTimeScanDirection { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(101)]
    [JsonPropertyName("RemediationScheduleDay")]
    internal byte? RemediationScheduleDay { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(102)]
    [JsonPropertyName("RemediationScheduleTime")]
    internal string? RemediationScheduleTime { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(103)]
    [JsonPropertyName("RemoteEncryptionProtectionAggressiveness")]
    internal byte? RemoteEncryptionProtectionAggressiveness { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(104)]
    [JsonPropertyName("RemoteEncryptionProtectionConfiguredState")]
    internal byte? RemoteEncryptionProtectionConfiguredState { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(105)]
    [JsonPropertyName("RemoteEncryptionProtectionExclusions")]
    internal List<string>? RemoteEncryptionProtectionExclusions { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(106)]
    [JsonPropertyName("RemoteEncryptionProtectionMaxBlockTime")]
    internal int? RemoteEncryptionProtectionMaxBlockTime { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(107)]
    [JsonPropertyName("RemoveScanningThreadPoolCap")]
    internal bool? RemoveScanningThreadPoolCap { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(108)]
    [JsonPropertyName("ReportDynamicSignatureDroppedEvent")]
    internal bool? ReportDynamicSignatureDroppedEvent { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(109)]
    [JsonPropertyName("ReportingAdditionalActionTimeOut")]
    internal int? ReportingAdditionalActionTimeOut { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(110)]
    [JsonPropertyName("ReportingCriticalFailureTimeOut")]
    internal int? ReportingCriticalFailureTimeOut { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(111)]
    [JsonPropertyName("ReportingNonCriticalTimeOut")]
    internal int? ReportingNonCriticalTimeOut { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(112)]
    [JsonPropertyName("ScanAvgCPULoadFactor")]
    internal byte? ScanAvgCPULoadFactor { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(113)]
    [JsonPropertyName("ScanOnlyIfIdleEnabled")]
    internal bool? ScanOnlyIfIdleEnabled { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(114)]
    [JsonPropertyName("ScanParameters")]
    internal byte? ScanParameters { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(115)]
    [JsonPropertyName("ScanPurgeItemsAfterDelay")]
    internal int? ScanPurgeItemsAfterDelay { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(116)]
    [JsonPropertyName("ScanScheduleDay")]
    internal byte? ScanScheduleDay { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(117)]
    [JsonPropertyName("ScanScheduleOffset")]
    internal int? ScanScheduleOffset { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(118)]
    [JsonPropertyName("ScanScheduleQuickScanTime")]
    internal string? ScanScheduleQuickScanTime { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(119)]
    [JsonPropertyName("ScanScheduleTime")]
    internal string? ScanScheduleTime { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(120)]
    [JsonPropertyName("SchedulerRandomizationTime")]
    internal int? SchedulerRandomizationTime { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(121)]
    [JsonPropertyName("ServiceHealthReportInterval")]
    internal int? ServiceHealthReportInterval { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(122)]
    [JsonPropertyName("SevereThreatDefaultAction")]
    internal byte? SevereThreatDefaultAction { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(123)]
    [JsonPropertyName("SharedSignaturesPath")]
    internal string? SharedSignaturesPath { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(124)]
    [JsonPropertyName("SharedSignaturesPathUpdateAtScheduledTimeOnly")]
    internal bool? SharedSignaturesPathUpdateAtScheduledTimeOnly { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(125)]
    [JsonPropertyName("SignatureAuGracePeriod")]
    internal int? SignatureAuGracePeriod { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(126)]
    [JsonPropertyName("SignatureBlobFileSharesSources")]
    internal string? SignatureBlobFileSharesSources { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(127)]
    [JsonPropertyName("SignatureBlobUpdateInterval")]
    internal int? SignatureBlobUpdateInterval { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(128)]
    [JsonPropertyName("SignatureDefinitionUpdateFileSharesSources")]
    internal string? SignatureDefinitionUpdateFileSharesSources { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(129)]
    [JsonPropertyName("SignatureDisableUpdateOnStartupWithoutEngine")]
    internal bool? SignatureDisableUpdateOnStartupWithoutEngine { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(130)]
    [JsonPropertyName("SignatureFallbackOrder")]
    internal string? SignatureFallbackOrder { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(131)]
    [JsonPropertyName("SignatureFirstAuGracePeriod")]
    internal int? SignatureFirstAuGracePeriod { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(132)]
    [JsonPropertyName("SignatureScheduleDay")]
    internal byte? SignatureScheduleDay { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(133)]
    [JsonPropertyName("SignatureScheduleTime")]
    internal string? SignatureScheduleTime { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(134)]
    [JsonPropertyName("SignatureUpdateCatchupInterval")]
    internal int? SignatureUpdateCatchupInterval { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(135)]
    [JsonPropertyName("SignatureUpdateInterval")]
    internal int? SignatureUpdateInterval { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(136)]
    [JsonPropertyName("SubmitSamplesConsent")]
    internal byte? SubmitSamplesConsent { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(137)]
    [JsonPropertyName("ThreatIDDefaultAction_Actions")]
    internal List<string>? ThreatIDDefaultAction_Actions { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(138)]
    [JsonPropertyName("ThreatIDDefaultAction_Ids")]
    internal List<string>? ThreatIDDefaultAction_Ids { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(139)]
    [JsonPropertyName("ThrottleForScheduledScanOnly")]
    internal bool? ThrottleForScheduledScanOnly { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(140)]
    [JsonPropertyName("TrustLabelProtectionStatus")]
    internal int? TrustLabelProtectionStatus { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(141)]
    [JsonPropertyName("UILockdown")]
    internal bool? UILockdown { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(142)]
    [JsonPropertyName("UnknownThreatDefaultAction")]
    internal byte? UnknownThreatDefaultAction { get; set; }
}

[JsonSourceGenerationOptions(WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(MpPreferences))]
internal sealed partial class MpPreferencesJsonContext : JsonSerializerContext
{
}

internal sealed partial class Program
{

    [LibraryImport("WMI.dll", EntryPoint = "get_mp_preferences_json", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr GetMpPreferencesJson();

    [LibraryImport("WMI.dll", EntryPoint = "free_json_string", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial void FreeJsonString(IntPtr s);

    static void Main()
    {
        IntPtr jsonPtr = GetMpPreferencesJson();
        if (jsonPtr == IntPtr.Zero)
        {
            Console.WriteLine("Failed to get JSON from Rust DLL.");
            return;
        }

        // Convert the pointer to a C# string.
        string? json = Marshal.PtrToStringAnsi(jsonPtr) ?? throw new InvalidOperationException("No JSON data was available!");

        // Free the allocated string in the Rust DLL.
        FreeJsonString(jsonPtr);

        MpPreferences? prefs = JsonSerializer.Deserialize(json, MpPreferencesJsonContext.Default.MpPreferences);

        Console.WriteLine(prefs);
    }
}
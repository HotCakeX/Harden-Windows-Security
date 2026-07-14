// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using AppControlManager.ViewModels;
using CommonCore.AppSettings;
using HardenSystemSecurity.WindowComponents;

namespace HardenSystemSecurity.ViewModels;

/// <summary>
/// Provides lazy initialization for all view models in the application.
/// This class serves as a centralized provider for view models using the Lazy<T> pattern.
/// </summary>
internal static class ViewModelProvider
{
	// View Models \\
	private static readonly Lazy<ProtectVM> _protectVM = new(() => new(), false);
	private static readonly Lazy<MainWindowVM> _mainWindowVM = new(() => new(), false);
	private static readonly Lazy<NavigationService> _navigationService = new(() => new(MainWindowVM), false);
	private static readonly Lazy<SettingsVM> _settingsVM = new(() => new(), false);
	private static readonly Lazy<LogsVM> _logsVM = new(() => new(), false);
	private static readonly Lazy<UpdateVM> _updateVM = new(() => new(), false);
	private static readonly Lazy<GroupPolicyEditorVM> _groupPolicyEditorVM = new(() => new(), false);
	private static readonly Lazy<MicrosoftDefenderVM> _microsoftDefenderVM = new(() => new(), false);
	private static readonly Lazy<ASRVM> _asrVM = new(() => new(), false);
	private static readonly Lazy<OptionalWindowsFeaturesVM> _optionalWindowsFeaturesVM = new(() => new(), false);
	private static readonly Lazy<WindowsUpdateVM> _windowsUpdateVM = new(() => new(), false);
	private static readonly Lazy<DeviceGuardVM> _deviceGuardVM = new(() => new(), false);
	private static readonly Lazy<EdgeVM> _edgeVM = new(() => new(), false);
	private static readonly Lazy<WindowsFirewallVM> _windowsFirewallVM = new(() => new(), false);
	private static readonly Lazy<UACVM> _uacVM = new(() => new(), false);
	private static readonly Lazy<TLSVM> _tLSVM = new(() => new(), false);
	private static readonly Lazy<LockScreenVM> _lockScreenVM = new(() => new(), false);
	private static readonly Lazy<MiscellaneousConfigsVM> _miscellaneousConfigsVM = new(() => new(), false);
	private static readonly Lazy<WindowsNetworkingVM> _windowsNetworkingVM = new(() => new(), false);
	private static readonly Lazy<NonAdminVM> _nonAdminVM = new(() => new(), false);
	private static readonly Lazy<BitLockerVM> _bitLockerVM = new(() => new(), false);
	private static readonly Lazy<CertificateCheckingVM> _certificateCheckingVM = new(() => new(), false);
	private static readonly Lazy<CountryIPBlockingVM> _countryIPBlockingVM = new(() => new(), false);
	private static readonly Lazy<FileReputationVM> _fileReputationVM = new(() => new(), false);
	private static readonly Lazy<InstalledAppsManagementVM> _installedAppsManagementVM = new(() => new(), false);
	private static readonly Lazy<WinGetManagementVM> _WinGetManagementVM = new(() => new(), false);
	private static readonly Lazy<MicrosoftSecurityBaselineVM> _microsoftSecurityBaselineVM = new(() => new(), false);
	private static readonly Lazy<Microsoft365AppsSecurityBaselineVM> _microsoft365AppsSecurityBaselineVM = new(() => new(), false);
	private static readonly Lazy<MicrosoftBaseLinesOverridesVM> _microsoftBaseLinesOverridesVM = new(() => new(), false);
	private static readonly Lazy<AuditPoliciesVM> _auditPoliciesVM = new(() => new(), false);
	private static readonly Lazy<HomeVM> _homeVM = new(() => new(), false);
	private static readonly Lazy<CryptographicBillOfMaterialsVM> _cryptographicBillOfMaterialsVM = new(() => new(), false);
	private static readonly Lazy<IntuneVM> _intuneVM = new(() => new(), false);
	private static readonly Lazy<IntuneDeploymentDetailsVM> _intuneDeploymentDetailsVM = new(() => new(), false);
	private static readonly Lazy<CSPVM> _cspVM = new(() => new(), false);
	private static readonly Lazy<DuplicatePhotoFinderVM> _duplicateImageFinderVM = new(() => new(), false);
	private static readonly Lazy<EXIFManagerVM> _eXIFManagerVM = new(() => new(), false);
	private static readonly Lazy<DownloadManagerVM> _downloadManagerVM = new(() => new(), false);
	private static readonly Lazy<ServiceManagerVM> _serviceManagerVM = new(() => new(), false);
	private static readonly Lazy<SystemShutdownInfoDialogVM> _systemShutdownInfoDialogVM = new(() => new(), false);
	private static readonly Lazy<BootableDriveMakerVM> _bootableDriveMakerVM = new(() => new(), false);
	private static readonly Lazy<ExploitMitigationsVM> _exploitMitigationsVM = new(() => new(), false);
	private static readonly Lazy<SandboxMakerVM> _sandboxMakerVM = new(() => new(), false);
	private static readonly Lazy<SettingsBackupRestoreVM> _settingsBackupRestore = new(() => new(), false);
	private static readonly Lazy<ViewExportedFunctionsVM> _viewExportedFunctionsVM = new(() => new(), false);

	// Internal Properties - View Models \\
	internal static ProtectVM ProtectVM => _protectVM.Value;
	internal static MainWindowVM MainWindowVM => _mainWindowVM.Value;
	internal static NavigationService NavigationService => _navigationService.Value;
	internal static SettingsVM SettingsVM => _settingsVM.Value;
	internal static LogsVM LogsVM => _logsVM.Value;
	internal static UpdateVM UpdateVM => _updateVM.Value;
	internal static MicrosoftDefenderVM MicrosoftDefenderVM => _microsoftDefenderVM.Value;
	internal static GroupPolicyEditorVM GroupPolicyEditorVM => _groupPolicyEditorVM.Value;
	internal static ASRVM ASRVM => _asrVM.Value;
	internal static OptionalWindowsFeaturesVM OptionalWindowsFeaturesVM => _optionalWindowsFeaturesVM.Value;
	internal static WindowsUpdateVM WindowsUpdateVM => _windowsUpdateVM.Value;
	internal static DeviceGuardVM DeviceGuardVM => _deviceGuardVM.Value;
	internal static EdgeVM EdgeVM => _edgeVM.Value;
	internal static WindowsFirewallVM WindowsFirewallVM => _windowsFirewallVM.Value;
	internal static UACVM UACVM => _uacVM.Value;
	internal static TLSVM TLSVM => _tLSVM.Value;
	internal static LockScreenVM LockScreenVM => _lockScreenVM.Value;
	internal static MiscellaneousConfigsVM MiscellaneousConfigsVM => _miscellaneousConfigsVM.Value;
	internal static WindowsNetworkingVM WindowsNetworkingVM => _windowsNetworkingVM.Value;
	internal static NonAdminVM NonAdminVM => _nonAdminVM.Value;
	internal static BitLockerVM BitLockerVM => _bitLockerVM.Value;
	internal static CertificateCheckingVM CertificateCheckingVM => _certificateCheckingVM.Value;
	internal static CountryIPBlockingVM CountryIPBlockingVM => _countryIPBlockingVM.Value;
	internal static FileReputationVM FileReputationVM => _fileReputationVM.Value;
	internal static InstalledAppsManagementVM InstalledAppsManagementVM => _installedAppsManagementVM.Value;
	internal static WinGetManagementVM WinGetManagementVM => _WinGetManagementVM.Value;
	internal static MicrosoftSecurityBaselineVM MicrosoftSecurityBaselineVM => _microsoftSecurityBaselineVM.Value;
	internal static Microsoft365AppsSecurityBaselineVM Microsoft365AppsSecurityBaselineVM => _microsoft365AppsSecurityBaselineVM.Value;
	internal static MicrosoftBaseLinesOverridesVM MicrosoftBaseLinesOverridesVM => _microsoftBaseLinesOverridesVM.Value;
	internal static AuditPoliciesVM AuditPoliciesVM => _auditPoliciesVM.Value;
	internal static HomeVM HomeVM => _homeVM.Value;
	internal static CryptographicBillOfMaterialsVM CryptographicBillOfMaterialsVM => _cryptographicBillOfMaterialsVM.Value;
	internal static IntuneVM IntuneVM => _intuneVM.Value;
	internal static IntuneDeploymentDetailsVM IntuneDeploymentDetailsVM => _intuneDeploymentDetailsVM.Value;
	internal static CSPVM CSPVM => _cspVM.Value;
	internal static DuplicatePhotoFinderVM DuplicatePhotoFinderVM => _duplicateImageFinderVM.Value;
	internal static EXIFManagerVM EXIFManagerVM => _eXIFManagerVM.Value;
	internal static DownloadManagerVM DownloadManagerVM => _downloadManagerVM.Value;
	internal static ServiceManagerVM ServiceManagerVM => _serviceManagerVM.Value;
	internal static SystemShutdownInfoDialogVM SystemShutdownInfoDialogVM => _systemShutdownInfoDialogVM.Value;
	internal static BootableDriveMakerVM BootableDriveMakerVM => _bootableDriveMakerVM.Value;
	internal static ExploitMitigationsVM ExploitMitigationsVM => _exploitMitigationsVM.Value;
	internal static SandboxMakerVM SandboxMakerVM => _sandboxMakerVM.Value;
	internal static SettingsBackupRestoreVM SettingsBackupRestore => _settingsBackupRestore.Value;
	internal static ViewExportedFunctionsVM ViewExportedFunctionsVM => _viewExportedFunctionsVM.Value;

	/// <summary>
	/// Disposes only those instances that were actually created during the app lifetime and implement <see cref="IDisposable"/>
	/// </summary>
	internal static void DisposeCreatedViewModels()
	{
		try { if (_logsVM.IsValueCreated) _logsVM.Value.Dispose(); } catch { }
		try { if (_optionalWindowsFeaturesVM.IsValueCreated) _optionalWindowsFeaturesVM.Value.Dispose(); } catch { }
		try { if (_WinGetManagementVM.IsValueCreated) _WinGetManagementVM.Value.Dispose(); } catch { }
		try { if (_homeVM.IsValueCreated) _homeVM.Value.Dispose(); } catch { }
		try { if (_intuneVM.IsValueCreated) _intuneVM.Value.Dispose(); } catch { }
	}
}

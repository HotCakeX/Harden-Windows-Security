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

using System.Threading;
using AppControlManager.ViewModels;
using HardenSystemSecurity.WindowComponents;
using Windows.Storage;

namespace HardenSystemSecurity.ViewModels;

/// <summary>
/// Provides lazy initialization for all view models in the application.
/// This class serves as a centralized provider for view models using the Lazy<T> pattern.
/// </summary>
internal static class ViewModelProvider
{
	// Core dependencies \\

	/// <summary>
	/// Initialized early during App startup by a single thread, doesn't need thread safety.
	/// </summary>
	private static readonly Lazy<AppSettings.Main> _appSettings = new(() =>
		new AppSettings.Main(ApplicationData.Current.LocalSettings), LazyThreadSafetyMode.None);

	// View Models \\
	private static readonly Lazy<ProtectVM> _protectVM = new(() =>
		new ProtectVM(), false);

	private static readonly Lazy<MainWindowVM> _mainWindowVM = new(() =>
		new MainWindowVM(), false);

	private static readonly Lazy<NavigationService> _navigationService = new(() =>
		new NavigationService(MainWindowVM), false);

	private static readonly Lazy<SettingsVM> _settingsVM = new(() =>
		new SettingsVM(), false);

	private static readonly Lazy<LogsVM> _logsVM = new(() =>
		new LogsVM(), false);

	private static readonly Lazy<UpdateVM> _updateVM = new(() =>
		new UpdateVM(), false);

	private static readonly Lazy<GroupPolicyEditorVM> _groupPolicyEditorVM = new(() =>
		new GroupPolicyEditorVM(), false);

	private static readonly Lazy<MicrosoftDefenderVM> _microsoftDefenderVM = new(() =>
		new MicrosoftDefenderVM(), false);

	private static readonly Lazy<ASRVM> _asrVM = new(() =>
		new ASRVM(), false);

	private static readonly Lazy<OptionalWindowsFeaturesVM> _optionalWindowsFeaturesVM = new(() =>
		new OptionalWindowsFeaturesVM(), false);

	private static readonly Lazy<WindowsUpdateVM> _windowsUpdateVM = new(() =>
		new WindowsUpdateVM(), false);

	private static readonly Lazy<DeviceGuardVM> _deviceGuardVM = new(() =>
		new DeviceGuardVM(), false);

	private static readonly Lazy<EdgeVM> _edgeVM = new(() =>
		new EdgeVM(), false);

	private static readonly Lazy<WindowsFirewallVM> _windowsFirewallVM = new(() =>
		new WindowsFirewallVM(), false);

	private static readonly Lazy<UACVM> _uacVM = new(() =>
		new UACVM(), false);

	private static readonly Lazy<TLSVM> _tLSVM = new(() =>
		new TLSVM(), false);

	private static readonly Lazy<LockScreenVM> _lockScreenVM = new(() =>
		new LockScreenVM(), false);

	private static readonly Lazy<MiscellaneousConfigsVM> _miscellaneousConfigsVM = new(() =>
		new MiscellaneousConfigsVM(), false);

	private static readonly Lazy<WindowsNetworkingVM> _windowsNetworkingVM = new(() =>
		new WindowsNetworkingVM(), false);

	private static readonly Lazy<NonAdminVM> _nonAdminVM = new(() =>
		new NonAdminVM(), false);

	private static readonly Lazy<BitLockerVM> _bitLockerVM = new(() =>
		new BitLockerVM(), false);

	private static readonly Lazy<CertificateCheckingVM> _certificateCheckingVM = new(() =>
		new CertificateCheckingVM(), false);

	private static readonly Lazy<CountryIPBlockingVM> _countryIPBlockingVM = new(() =>
		new CountryIPBlockingVM(), false);

	private static readonly Lazy<FileReputationVM> _fileReputationVM = new(() =>
		new FileReputationVM(), false);

	private static readonly Lazy<InstalledAppsManagementVM> _installedAppsManagementVM = new(() =>
		new InstalledAppsManagementVM(), false);

	private static readonly Lazy<MicrosoftSecurityBaselineVM> _microsoftSecurityBaselineVM = new(() =>
		new MicrosoftSecurityBaselineVM(), false);

	private static readonly Lazy<Microsoft365AppsSecurityBaselineVM> _microsoft365AppsSecurityBaselineVM = new(() =>
		new Microsoft365AppsSecurityBaselineVM(), false);

	private static readonly Lazy<MicrosoftBaseLinesOverridesVM> _microsoftBaseLinesOverridesVM = new(() =>
		new MicrosoftBaseLinesOverridesVM(), false);

	private static readonly Lazy<AuditPoliciesVM> _auditPoliciesVM = new(() =>
		new AuditPoliciesVM(), false);

	private static readonly Lazy<HomeVM> _homeVM = new(() =>
		new HomeVM(), false);

	private static readonly Lazy<CryptographicBillOfMaterialsVM> _cryptographicBillOfMaterialsVM = new(() =>
		new CryptographicBillOfMaterialsVM(), false);

	// Internal Properties - Core Dependencies \\
	internal static AppSettings.Main AppSettings => _appSettings.Value;

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
	internal static MicrosoftSecurityBaselineVM MicrosoftSecurityBaselineVM => _microsoftSecurityBaselineVM.Value;
	internal static Microsoft365AppsSecurityBaselineVM Microsoft365AppsSecurityBaselineVM => _microsoft365AppsSecurityBaselineVM.Value;
	internal static MicrosoftBaseLinesOverridesVM MicrosoftBaseLinesOverridesVM => _microsoftBaseLinesOverridesVM.Value;
	internal static AuditPoliciesVM AuditPoliciesVM => _auditPoliciesVM.Value;
	internal static HomeVM HomeVM => _homeVM.Value;
	internal static CryptographicBillOfMaterialsVM CryptographicBillOfMaterialsVM => _cryptographicBillOfMaterialsVM.Value;


	/// <summary>
	/// Disposes only those instances that were actually created during the app lifetime and implement <see cref="IDisposable"/>
	/// </summary>
	internal static void DisposeCreatedViewModels()
	{
		try
		{
			if (_logsVM.IsValueCreated) _logsVM.Value.Dispose();
		}
		catch { }
	}
}

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
using AppControlManager.Others;
using AppControlManager.WindowComponents;
using CommonCore.AppSettings;

namespace AppControlManager.ViewModels;

/// <summary>
/// Provides lazy initialization for all view models in the application.
/// This class serves as a centralized provider for view models using the Lazy<T> pattern.
/// </summary>
internal static class ViewModelProvider
{
	// Core dependencies \\

	private static readonly Lazy<EventLogUtility> _eventLogUtility = new(() => new(), LazyThreadSafetyMode.PublicationOnly);

	// View Models \\
	private static readonly Lazy<SidebarVM> _sidebarVM = new(() => new(), false);
	private static readonly Lazy<ViewCurrentPoliciesVM> _viewCurrentPoliciesVM = new(() => new(), false);
	private static readonly Lazy<SettingsVM> _settingsVM = new(() => new(), false);
	private static readonly Lazy<MergePoliciesVM> _mergePoliciesVM = new(() => new(), false);
	private static readonly Lazy<ComparePoliciesVM> _comparePoliciesVM = new(() => new(), false);
	private static readonly Lazy<ConfigurePolicyRuleOptionsVM> _configurePolicyRuleOptionsVM = new(() => new(), false);
	private static readonly Lazy<CreateDenyPolicyVM> _createDenyPolicyVM = new(() => new(), false);
	private static readonly Lazy<CreateSupplementalPolicyVM> _createSupplementalPolicyVM = new(() => new(), false);
	private static readonly Lazy<EventLogsPolicyCreationVM> _eventLogsPolicyCreationVM = new(() => new(), false);
	private static readonly Lazy<SimulationVM> _simulationVM = new(() => new(), false);
	private static readonly Lazy<MDEAHPolicyCreationVM> _mdeahPolicyCreationVM = new(() => new(), false);
	private static readonly Lazy<ViewFileCertificatesVM> _viewFileCertificatesVM = new(() => new(), false);
	private static readonly Lazy<CreatePolicyVM> _createPolicyVM = new(() => new(), false);
	private static readonly Lazy<DeploymentVM> _deploymentVM = new(() => new(), false);
	private static readonly Lazy<UpdateVM> _updateVM = new(() => new(), false);
	private static readonly Lazy<ValidatePolicyVM> _validatePolicyVM = new(() => new(), false);
	private static readonly Lazy<CodeIntegrityInfoVM> _codeIntegrityInfoVM = new(() => new(), false);
	private static readonly Lazy<GetCIHashesVM> _getCIHashesVM = new(() => new(), false);
	private static readonly Lazy<BuildNewCertificateVM> _buildNewCertificateVM = new(() => new(), false);
	private static readonly Lazy<GetSecurePolicySettingsVM> _getSecurePolicySettingsVM = new(() => new(), false);
	private static readonly Lazy<LogsVM> _logsVM = new(() => new(), false);
	private static readonly Lazy<IntuneDeploymentDetailsVM> _intuneDeploymentDetailsVM = new(() => new(), false);
	private static readonly Lazy<HomeVM> _homeVM = new(() => new(), false);
	// View Models with Dependencies \\
	private static readonly Lazy<PolicyEditorVM> _policyEditorVM = new(() => new(), false);
	private static readonly Lazy<AllowNewAppsVM> _allowNewAppsVM = new(() => new(EventLogUtility, PolicyEditorVM), false);
	private static readonly Lazy<MainWindowVM> _mainWindowVM = new(() => new(), false);
	private static readonly Lazy<NavigationService> _navigationService = new(() => new(MainWindowVM, SidebarVM), false);
	private static readonly Lazy<ViewOnlinePoliciesVM> _viewOnlinePoliciesVM = new(() => new(), false);
	private static readonly Lazy<FirewallSentinelVM> _firewallSentinelVM = new(() => new(), false);
	private static readonly Lazy<SystemShutdownInfoDialogVM> _systemShutdownInfoDialogVM = new(() => new(), false);
	private static readonly Lazy<SettingsBackupRestoreVM> _settingsBackupRestore = new(() => new(), false);
	// Core Dependencies \\
	internal static EventLogUtility EventLogUtility => _eventLogUtility.Value;

	// View Models \\
	internal static SidebarVM SidebarVM => _sidebarVM.Value;
	internal static ViewCurrentPoliciesVM ViewCurrentPoliciesVM => _viewCurrentPoliciesVM.Value;
	internal static SettingsVM SettingsVM => _settingsVM.Value;
	internal static MergePoliciesVM MergePoliciesVM => _mergePoliciesVM.Value;
	internal static ComparePoliciesVM ComparePoliciesVM => _comparePoliciesVM.Value;
	internal static ConfigurePolicyRuleOptionsVM ConfigurePolicyRuleOptionsVM => _configurePolicyRuleOptionsVM.Value;
	internal static AllowNewAppsVM AllowNewAppsVM => _allowNewAppsVM.Value;
	internal static CreateDenyPolicyVM CreateDenyPolicyVM => _createDenyPolicyVM.Value;
	internal static CreateSupplementalPolicyVM CreateSupplementalPolicyVM => _createSupplementalPolicyVM.Value;
	internal static EventLogsPolicyCreationVM EventLogsPolicyCreationVM => _eventLogsPolicyCreationVM.Value;
	internal static SimulationVM SimulationVM => _simulationVM.Value;
	internal static MDEAHPolicyCreationVM MDEAHPolicyCreationVM => _mdeahPolicyCreationVM.Value;
	internal static ViewFileCertificatesVM ViewFileCertificatesVM => _viewFileCertificatesVM.Value;
	internal static MainWindowVM MainWindowVM => _mainWindowVM.Value;
	internal static CreatePolicyVM CreatePolicyVM => _createPolicyVM.Value;
	internal static DeploymentVM DeploymentVM => _deploymentVM.Value;
	internal static UpdateVM UpdateVM => _updateVM.Value;
	internal static ValidatePolicyVM ValidatePolicyVM => _validatePolicyVM.Value;
	internal static CodeIntegrityInfoVM CodeIntegrityInfoVM => _codeIntegrityInfoVM.Value;
	internal static GetCIHashesVM GetCIHashesVM => _getCIHashesVM.Value;
	internal static NavigationService NavigationService => _navigationService.Value;
	internal static ViewOnlinePoliciesVM ViewOnlinePoliciesVM => _viewOnlinePoliciesVM.Value;
	internal static PolicyEditorVM PolicyEditorVM => _policyEditorVM.Value;
	internal static BuildNewCertificateVM BuildNewCertificateVM => _buildNewCertificateVM.Value;
	internal static GetSecurePolicySettingsVM GetSecurePolicySettingsVM => _getSecurePolicySettingsVM.Value;
	internal static LogsVM LogsVM => _logsVM.Value;
	internal static IntuneDeploymentDetailsVM IntuneDeploymentDetailsVM => _intuneDeploymentDetailsVM.Value;
	internal static HomeVM HomeVM => _homeVM.Value;
	internal static FirewallSentinelVM FirewallSentinelVM => _firewallSentinelVM.Value;
	internal static SystemShutdownInfoDialogVM SystemShutdownInfoDialogVM => _systemShutdownInfoDialogVM.Value;
	internal static SettingsBackupRestoreVM SettingsBackupRestore => _settingsBackupRestore.Value;

	/// <summary>
	/// Disposes only those instances that were actually created during the app lifetime and implement <see cref="IDisposable"/>
	/// </summary>
	internal static void DisposeCreatedViewModels()
	{
		try
		{
			if (_createDenyPolicyVM.IsValueCreated) _createDenyPolicyVM.Value.Dispose();
		}
		catch { }

		try
		{
			if (_deploymentVM.IsValueCreated) _deploymentVM.Value.Dispose();
		}
		catch { }

		try
		{
			if (_logsVM.IsValueCreated) _logsVM.Value.Dispose();
		}
		catch { }

		try
		{
			if (_mdeahPolicyCreationVM.IsValueCreated) _mdeahPolicyCreationVM.Value.Dispose();
		}
		catch { }

		try
		{
			if (_viewOnlinePoliciesVM.IsValueCreated) _viewOnlinePoliciesVM.Value.Dispose();
		}
		catch { }

		try
		{
			if (_createSupplementalPolicyVM.IsValueCreated) _createSupplementalPolicyVM.Value.Dispose();
		}
		catch { }
	}
}

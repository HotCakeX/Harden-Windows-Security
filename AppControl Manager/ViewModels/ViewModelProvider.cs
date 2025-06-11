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

using System;
using System.Threading;
using AppControlManager.MicrosoftGraph;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
using Windows.Storage;

namespace AppControlManager;

/// <summary>
/// Provides thread-safe lazy initialization for all view models in the application.
/// This class serves as a centralized provider for view models using the Lazy<T> pattern.
/// </summary>
internal static class ViewModelProvider
{
	// Core dependencies \\
	private static readonly Lazy<AppSettings.Main> _appSettings = new(() =>
		new AppSettings.Main(ApplicationData.Current.LocalSettings), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<EventLogUtility> _eventLogUtility = new(() =>
		new EventLogUtility(), LazyThreadSafetyMode.ExecutionAndPublication);

	// View Models \\
	private static readonly Lazy<SidebarVM> _sidebarVM = new(() =>
		new SidebarVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<ViewCurrentPoliciesVM> _viewCurrentPoliciesVM = new(() =>
		new ViewCurrentPoliciesVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<SettingsVM> _settingsVM = new(() =>
		new SettingsVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<MergePoliciesVM> _mergePoliciesVM = new(() =>
		new MergePoliciesVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<ConfigurePolicyRuleOptionsVM> _configurePolicyRuleOptionsVM = new(() =>
		new ConfigurePolicyRuleOptionsVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<CreateDenyPolicyVM> _createDenyPolicyVM = new(() =>
		new CreateDenyPolicyVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<CreateSupplementalPolicyVM> _createSupplementalPolicyVM = new(() =>
		new CreateSupplementalPolicyVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<EventLogsPolicyCreationVM> _eventLogsPolicyCreationVM = new(() =>
		new EventLogsPolicyCreationVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<SimulationVM> _simulationVM = new(() =>
		new SimulationVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<MDEAHPolicyCreationVM> _mdeahPolicyCreationVM = new(() =>
		new MDEAHPolicyCreationVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<ViewFileCertificatesVM> _viewFileCertificatesVM = new(() =>
		new ViewFileCertificatesVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<CreatePolicyVM> _createPolicyVM = new(() =>
		new CreatePolicyVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<DeploymentVM> _deploymentVM = new(() =>
		new DeploymentVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<UpdateVM> _updateVM = new(() =>
		new UpdateVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<ValidatePolicyVM> _validatePolicyVM = new(() =>
		new ValidatePolicyVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<CodeIntegrityInfoVM> _codeIntegrityInfoVM = new(() =>
		new CodeIntegrityInfoVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<GetCIHashesVM> _getCIHashesVM = new(() =>
		new GetCIHashesVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<ViewModelForMSGraph> _viewModelForMSGraph = new(() =>
		new ViewModelForMSGraph(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<BuildNewCertificateVM> _buildNewCertificateVM = new(() =>
		new BuildNewCertificateVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<GetSecurePolicySettingsVM> _getSecurePolicySettingsVM = new(() =>
		new GetSecurePolicySettingsVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<LogsVM> _logsVM = new(() =>
		new LogsVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	// View Models with Dependencies \\
	private static readonly Lazy<PolicyEditorVM> _policyEditorVM = new(() =>
		new PolicyEditorVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<AllowNewAppsVM> _allowNewAppsVM = new(() =>
		new AllowNewAppsVM(EventLogUtility, PolicyEditorVM), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<MainWindowVM> _mainWindowVM = new(() =>
		new MainWindowVM(), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<NavigationService> _navigationService = new(() =>
		new NavigationService(MainWindowVM, SidebarVM), LazyThreadSafetyMode.ExecutionAndPublication);

	private static readonly Lazy<ViewOnlinePoliciesVM> _viewOnlinePoliciesVM = new(() =>
		new ViewOnlinePoliciesVM(ViewModelForMSGraph), LazyThreadSafetyMode.ExecutionAndPublication);

	// Internal Properties - Core Dependencies \\
	internal static AppSettings.Main AppSettings => _appSettings.Value;
	internal static EventLogUtility EventLogUtility => _eventLogUtility.Value;

	// Internal Properties - View Models \\
	internal static SidebarVM SidebarVM => _sidebarVM.Value;
	internal static ViewCurrentPoliciesVM ViewCurrentPoliciesVM => _viewCurrentPoliciesVM.Value;
	internal static SettingsVM SettingsVM => _settingsVM.Value;
	internal static MergePoliciesVM MergePoliciesVM => _mergePoliciesVM.Value;
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
	internal static ViewModelForMSGraph ViewModelForMSGraph => _viewModelForMSGraph.Value;
	internal static ViewOnlinePoliciesVM ViewOnlinePoliciesVM => _viewOnlinePoliciesVM.Value;
	internal static PolicyEditorVM PolicyEditorVM => _policyEditorVM.Value;
	internal static BuildNewCertificateVM BuildNewCertificateVM => _buildNewCertificateVM.Value;
	internal static GetSecurePolicySettingsVM GetSecurePolicySettingsVM => _getSecurePolicySettingsVM.Value;
	internal static LogsVM LogsVM => _logsVM.Value;
}

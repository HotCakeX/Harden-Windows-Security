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

using System.Collections.Generic;
using AppControlManager.Others;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812, CA1822 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class ConfigurePolicyRuleOptionsVM : ViewModelBase
{
	internal Visibility BrowseForXMLPolicyButtonLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool IsElevated => App.IsElevated;

	/// <summary>
	/// To store the selected policy path
	/// </summary>
	internal string? SelectedFilePath { get; set => SP(ref field, value); }

	internal readonly Dictionary<string, string> RuleOptions = new()
	{
		{ "Enabled:UMCI", GlobalVars.Rizz.GetString("RuleOption_EnabledUMCI") },
		{ "Enabled:Boot Menu Protection", GlobalVars.Rizz.GetString("RuleOption_EnabledBootMenuProtection") },
		{ "Required:WHQL", GlobalVars.Rizz.GetString("RuleOption_RequiredWHQL") },
		{ "Enabled:Audit Mode", GlobalVars.Rizz.GetString("RuleOption_EnabledAuditMode") },
		{ "Disabled:Flight Signing", GlobalVars.Rizz.GetString("RuleOption_DisabledFlightSigning") },
		{ "Enabled:Inherit Default Policy", GlobalVars.Rizz.GetString("RuleOption_EnabledInheritDefaultPolicy") },
		{ "Enabled:Unsigned System Integrity Policy", GlobalVars.Rizz.GetString("RuleOption_EnabledUnsignedSystemIntegrityPolicy") },
		{ "Required:EV Signers", GlobalVars.Rizz.GetString("RuleOption_RequiredEVSigners") },
		{ "Enabled:Advanced Boot Options Menu", GlobalVars.Rizz.GetString("RuleOption_EnabledAdvancedBootOptionsMenu") },
		{ "Enabled:Boot Audit On Failure", GlobalVars.Rizz.GetString("RuleOption_EnabledBootAuditOnFailure") },
		{ "Disabled:Script Enforcement", GlobalVars.Rizz.GetString("RuleOption_DisabledScriptEnforcement") },
		{ "Required:Enforce Store Applications", GlobalVars.Rizz.GetString("RuleOption_RequiredEnforceStoreApplications") },
		{ "Enabled:Managed Installer", GlobalVars.Rizz.GetString("RuleOption_EnabledManagedInstaller") },
		{ "Enabled:Intelligent Security Graph Authorization", GlobalVars.Rizz.GetString("RuleOption_EnabledIntelligentSecurityGraphAuthorization") },
		{ "Enabled:Invalidate EAs on Reboot", GlobalVars.Rizz.GetString("RuleOption_EnabledInvalidateEAsOnReboot") },
		{ "Enabled:Update Policy No Reboot", GlobalVars.Rizz.GetString("RuleOption_EnabledUpdatePolicyNoReboot") },
		{ "Enabled:Allow Supplemental Policies", GlobalVars.Rizz.GetString("RuleOption_EnabledAllowSupplementalPolicies") },
		{ "Disabled:Runtime FilePath Rule Protection", GlobalVars.Rizz.GetString("RuleOption_DisabledRuntimeFilePathRuleProtection") },
		{ "Enabled:Dynamic Code Security",GlobalVars.Rizz.GetString("RuleOption_EnabledDynamicCodeSecurity") },
		{ "Enabled:Revoked Expired As Unsigned", GlobalVars.Rizz.GetString("RuleOption_EnabledRevokedExpiredAsUnsigned") },
		{ "Enabled:Developer Mode Dynamic Code Trust", GlobalVars.Rizz.GetString("RuleOption_EnabledDeveloperModeDynamicCodeTrust") },
		{ "Enabled:Secure Setting Policy", GlobalVars.Rizz.GetString("RuleOption_EnabledSecureSettingPolicy") },
		{ "Enabled:Conditional Windows Lockdown Policy", GlobalVars.Rizz.GetString("RuleOption_EnabledConditionalWindowsLockdownPolicy") }
	};
}

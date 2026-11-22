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
using System.Threading;
using System.Threading.Tasks;
using CommonCore.GroupPolicy;
using CommonCore.ToolKits;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using Microsoft.Win32;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class EdgeVM : MUnitListViewModelBase
{
	/// <summary>
	/// Creates all MUnits for this ViewModel.
	/// </summary>
	private static readonly Lazy<List<MUnit>> LazyCatalog =
		new(static () =>
		{
			// Register specialized strategies.
			RegisterSpecializedStrategies();

			// Need to enable Windows Protected Print when enabling DynamicCodeSettings for Edge
			// https://github.com/HotCakeX/Harden-Windows-Security/issues/1160
			MUnitDependencyRegistry.RegisterDependency(
				primaryMUnitId: new("019a8dfa-2460-70c9-8579-bfcf1b4a6122"),
				dependentMUnitId: new("019a8dfa-25da-7c9a-87e2-07fa9df81fff"),
				type: DependencyType.Apply,
				timing: ExecutionTiming.Before
			);

			return MUnit.CreateMUnitsFromPolicies(Categories.EdgeBrowserConfigurations);
		}, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// Gets the current catalog of all MUnits for this ViewModel.
	/// </summary>
	public override List<MUnit> AllMUnits => LazyCatalog.Value;

	/// <summary>
	/// Registers specialized strategies for specific policies.
	/// </summary>
	private static void RegisterSpecializedStrategies()
	{
		// Register specialized remove strategy for TLSCipherSuiteDenyList.
		// Because "Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList" must be deleted if empty.
		// Otherwise Edge will still think it is being controlled by an organization.
		// So after the removal of each of these values, there will be a check to see if that key is empty or not and if it's empty, it'll be deleted.
		SpecializedStrategiesRegistry.RegisterSpecializedRemove(
			"SOFTWARE\\Policies\\Microsoft\\Edge\\TLSCipherSuiteDenyList|1",
			new TLSCipherSuiteDenyListPostRemoveCleanup()
		);
		SpecializedStrategiesRegistry.RegisterSpecializedRemove(
			"SOFTWARE\\Policies\\Microsoft\\Edge\\TLSCipherSuiteDenyList|2",
			new TLSCipherSuiteDenyListPostRemoveCleanup()
		);
		SpecializedStrategiesRegistry.RegisterSpecializedRemove(
			"SOFTWARE\\Policies\\Microsoft\\Edge\\TLSCipherSuiteDenyList|3",
			new TLSCipherSuiteDenyListPostRemoveCleanup()
		);
		SpecializedStrategiesRegistry.RegisterSpecializedRemove(
			"SOFTWARE\\Policies\\Microsoft\\Edge\\TLSCipherSuiteDenyList|4",
			new TLSCipherSuiteDenyListPostRemoveCleanup()
		);
		SpecializedStrategiesRegistry.RegisterSpecializedRemove(
			"SOFTWARE\\Policies\\Microsoft\\Edge\\TLSCipherSuiteDenyList|5",
			new TLSCipherSuiteDenyListPostRemoveCleanup()
		);
		SpecializedStrategiesRegistry.RegisterSpecializedRemove(
			"SOFTWARE\\Policies\\Microsoft\\Edge\\TLSCipherSuiteDenyList|6",
			new TLSCipherSuiteDenyListPostRemoveCleanup()
		);
	}

	/// <summary>
	/// Specialized remove strategy that runs after the main remove operation.
	/// </summary>
	private sealed class TLSCipherSuiteDenyListPostRemoveCleanup : ISpecializedRemoveStrategy
	{
		public ExecutionTiming Timing => ExecutionTiming.After;

		public void Remove()
		{
			using RegistryKey? TLSCipherSuiteDenyListSubKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList", false);

			if (TLSCipherSuiteDenyListSubKey is not null)
			{
				string[] TLSCipherSuiteDenyListItems = TLSCipherSuiteDenyListSubKey.GetValueNames();

				if (TLSCipherSuiteDenyListItems.Length == 0)
				{
					Registry.LocalMachine.DeleteSubKey(@"SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList");
				}
			}
		}
	}

	#region Management Tab

	private const string EdgePolicyKey = @"SOFTWARE\Policies\Microsoft\Edge";
	private static readonly Guid DnsModeId = new("01a20386-5202-75e5-b4e2-b6bc52dd9e38");

	// A negative selection represents an absent or unrecognized policy, not automatic mode.
	internal int DnsModeSelectedIndex { get; set => SP(ref field, value); } = -1;

	internal string DnsTemplates { get; set => SP(ref field, value); } = string.Empty;

	/// <summary>
	/// Selected Edge tab. The management tab is index 1 in the page's fixed tab order.
	/// </summary>
	internal int SelectedTabIndex { get; set => SP(ref field, value); }

	/// <summary>
	/// Creates a separate registry entry without changing the shared hardening catalog.
	/// </summary>
	private static RegistryPolicyEntry CreateDnsPolicy(string valueName, string? value) => new(
		source: Source.Registry,
		keyName: EdgePolicyKey,
		valueName: valueName,
		type: RegistryValueType.REG_SZ,
		size: 0,
		data: ReadOnlyMemory<byte>.Empty,
		hive: Hive.HKLM,
		id: DnsModeId)
	{
		RegValue = value
	};

	/// <summary>
	/// Reads the machine policy without substituting a default for a missing value.
	/// </summary>
	private static (string? Mode, string? Templates) ReadDnsPolicies() => (
		CommonCore.RegistryManager.Manager.ReadRegistry(CreateDnsPolicy("DnsOverHttpsMode", null)),
		CommonCore.RegistryManager.Manager.ReadRegistry(CreateDnsPolicy("DnsOverHttpsTemplates", null)));

	private void DisplayDnsPolicies(string? mode, string? templates)
	{
		DnsModeSelectedIndex = string.Equals(mode, "automatic", StringComparison.OrdinalIgnoreCase) ? 0
			: string.Equals(mode, "secure", StringComparison.OrdinalIgnoreCase) ? 1
			: string.Equals(mode, "off", StringComparison.OrdinalIgnoreCase) ? 2 : -1;
		DnsTemplates = templates ?? string.Empty;
	}

	/// <summary>
	/// XAML event handler.
	/// </summary>
	internal async void RetrieveDnsPolicies() => await ProcessDnsPoliciesAsync(false);

	/// <summary>
	/// XAML event handler for committing both related policy values.
	/// </summary>
	internal async void ApplyDnsPolicies() => await ProcessDnsPoliciesAsync(true);

	/// <summary>
	/// Normalizes resolver separators and performs basic URI-template checks.
	/// Edge remains the authority for full URI-template validity and resolver reachability.
	/// </summary>
	private static string NormalizeDnsTemplates(string input)
	{
		if (input.Contains('\0'))
			throw new ArgumentException("DNS-over-HTTPS templates cannot contain a null character.");

		string[] templates = input.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);

		foreach (string template in templates)
		{
			System.Text.StringBuilder expanded = new(template.Length);
			for (int i = 0; i < template.Length; i++)
			{
				char character = template[i];
				if (character == '}')
					throw new ArgumentException("A DNS-over-HTTPS template contains an unmatched closing brace.");

				if (character != '{')
				{
					_ = expanded.Append(character);
					continue;
				}

				int end = template.IndexOf('}', i + 1);

				if (end < 0 || end == i + 1 || template.AsSpan(i + 1, end - i - 1).IndexOf('{') >= 0)
					throw new ArgumentException("A DNS-over-HTTPS template contains an invalid variable expression.");

				// Use a harmless placeholder only for URI structure checks, never for the stored value.
				_ = expanded.Append("dns");
				i = end;
			}
			if (!Uri.TryCreate(expanded.ToString(), UriKind.Absolute, out Uri? uri)
				|| !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
				|| string.IsNullOrEmpty(uri.Host) || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0)
				throw new ArgumentException("Each DNS-over-HTTPS template must be an absolute HTTPS URI without credentials or a fragment.");
		}
		return string.Join(' ', templates);
	}

	/// <summary>
	/// Applies templates before enabling secure mode, or changes mode before removing templates.
	/// </summary>
	internal async Task ProcessDnsPoliciesAsync(bool apply)
	{
		if (!ElementsAreEnabled)
			return;

		ElementsAreEnabled = false;
		MainInfoBar.IsClosable = false;
		try
		{
			using IDisposable taskTracker = TaskTracking.RegisterOperation();
			if (!apply)
			{
				(string? Mode, string? Templates) = await Task.Run(ReadDnsPolicies);
				DisplayDnsPolicies(Mode, Templates);
				return;
			}
			string mode = DnsModeSelectedIndex switch
			{
				0 => "automatic",
				1 => "secure",
				2 => "off",
				_ => throw new ArgumentException("Select automatic, secure, or off before applying the policy.")
			};
			string templates = NormalizeDnsTemplates(DnsTemplates);

			if (string.Equals(mode, "secure", StringComparison.OrdinalIgnoreCase) && templates.Length == 0)
				throw new ArgumentException("Secure mode requires at least one DNS-over-HTTPS resolver template.");

			(string? Mode, string? Templates) actual = await Task.Run(() =>
			{
				RegistryPolicyEntry modePolicy = CreateDnsPolicy("DnsOverHttpsMode", mode);
				RegistryPolicyEntry templatePolicy = CreateDnsPolicy("DnsOverHttpsTemplates", templates);

				if (templates.Length > 0)
					CommonCore.RegistryManager.Manager.AddPoliciesToSystem([templatePolicy]);

				CommonCore.RegistryManager.Manager.AddPoliciesToSystem([modePolicy]);

				if (templates.Length == 0)
					CommonCore.RegistryManager.Manager.RemovePoliciesFromSystem([templatePolicy]);

				(string? Mode, string? Templates) stored = ReadDnsPolicies();

				if (!string.Equals(stored.Mode, mode, StringComparison.OrdinalIgnoreCase)
					|| (templates.Length == 0 ? stored.Templates is not null
						: !string.Equals(stored.Templates, templates, StringComparison.OrdinalIgnoreCase)))
					throw new InvalidOperationException("The stored DNS-over-HTTPS policies did not match the requested settings. Refresh to inspect the current values.");

				return stored;
			});
			DisplayDnsPolicies(actual.Mode, actual.Templates);

			MainInfoBar.WriteSuccess("DNS-over-HTTPS policies were saved successfully.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBar.IsClosable = true;
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Navigates through the existing navigation service and selects Management on the UI thread.
	/// </summary>
	internal async Task NavigateToManagementAsync()
	{
		await Atlas.AppDispatcher.EnqueueAsync(async () =>
		{
			await ViewModelProvider.NavigationService.Navigate(typeof(Pages.Protects.Edge));
			if (SelectedTabIndex == 1)
			{
				// Selecting an already selected tab does not raise SelectionChanged.
				await ProcessDnsPoliciesAsync(false);
			}
			else
			{
				// The existing selection handler refreshes the editors when the tab changes.
				SelectedTabIndex = 1;
			}
		});
	}

	#endregion

}

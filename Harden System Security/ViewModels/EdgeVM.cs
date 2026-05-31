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
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using CommonCore.GroupPolicy;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using Microsoft.Win32;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class EdgeVM : MUnitListViewModelBase
{

	[SetsRequiredMembers]
	internal EdgeVM()
	{
		MainInfoBar = new();

		// Initializing the cancellable buttons
		ApplyAllCancellableButton = new(Atlas.GetStr("ApplyAllButtonText/Text"));
		RemoveAllCancellableButton = new(Atlas.GetStr("RemoveAllButtonText/Text"));
		VerifyAllCancellableButton = new(Atlas.GetStr("VerifyAllButtonText"));

		IMUnitListViewModel.CreateUIValuesCategories(this);
	}

	/// <summary>
	/// Creates all MUnits for this ViewModel.
	/// </summary>
	private static readonly Lazy<List<MUnit>> LazyCatalog =
		new(() =>
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

}

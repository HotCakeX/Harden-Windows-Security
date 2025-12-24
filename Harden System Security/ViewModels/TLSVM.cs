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
using System.Linq;
using System.Threading;
using HardenSystemSecurity.GroupPolicy;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class TLSVM : MUnitListViewModelBase
{
	[SetsRequiredMembers]
	internal TLSVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// Initializing the cancellable buttons
		ApplyAllCancellableButton = new(GlobalVars.GetStr("ApplyAllButtonText/Text"));
		RemoveAllCancellableButton = new(GlobalVars.GetStr("RemoveAllButtonText/Text"));
		VerifyAllCancellableButton = new(GlobalVars.GetStr("VerifyAllButtonText"));

		IMUnitListViewModel.CreateUIValuesCategories(this);
	}

	/// <summary>
	/// Creates all MUnits for this ViewModel.
	/// </summary>
	private static readonly Lazy<List<MUnit>> LazyCatalog =
		new(() =>
		{

			#region One-time global registrations for this category - Registers specialized strategies for specific policies.

			// Register specialized verification strategy for TLS Cipher Suites so its details can be detected via Native API call too.
			SpecializedStrategiesRegistry.RegisterSpecializedVerification(
				"SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002|Functions",
				new TLSCipherSuites()
			);

			#endregion

			return MUnit.CreateMUnitsFromPolicies(Categories.TLSSecurity);
		}, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// Gets the current catalog of all MUnits for this ViewModel.
	/// </summary>
	public override List<MUnit> AllMUnits => LazyCatalog.Value;


	/// <summary>
	/// Specialized verification for TLS Cipher Suites.
	/// </summary>
	private sealed class TLSCipherSuites : ISpecializedVerificationStrategy
	{
		public bool Verify(RegistryPolicyEntry? targetPolicy = null)
		{
			try
			{
				if (targetPolicy is null || targetPolicy.RegValue is null)
					return false;

				// Use the RegValue directly from the target policy that invoked this fallback to ensure we verify against the specific expected state
				string cipherSuitesValue = targetPolicy.RegValue;

				// Parse the configured cipher suites into a HashSet
				HashSet<string> configuredCipherSuites = cipherSuitesValue.Split([','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet(StringComparer.OrdinalIgnoreCase);

				// Get the list of currently configured cipher suites via Arcane library
				List<Arcane.TlsCipherSuite> results = Arcane.CipherSuiteManager.EnumerateConfiguredCipherSuites();

				// Check if the counts match first
				if (configuredCipherSuites.Count != results.Count)
				{
					return false;
				}

				// Verify that all system cipher suites are in the policy configuration.
				foreach (Arcane.TlsCipherSuite item in results)
				{
					if (!configuredCipherSuites.Contains(item.Name))
					{
						// A system cipher suite is present that is not in the policy
						return false;
					}
				}

				// Exact match found
				return true;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return false;
			}
		}
	}
}

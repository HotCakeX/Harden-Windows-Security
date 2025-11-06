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
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class WindowsUpdateVM : MUnitListViewModelBase
{
	[SetsRequiredMembers]
	internal WindowsUpdateVM()
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
			#region Registers specialized strategies for specific policies.

			// Register specialized verification strategy for "Allow updates to be downloaded automatically over metered connections"
			// so its status can be detected via COM too.
			SpecializedStrategiesRegistry.RegisterSpecializedVerification(
				"Software\\Policies\\Microsoft\\Windows\\WindowsUpdate|AllowAutoWindowsUpdateDownloadOverMeteredNetwork",
				new AllowAutoWindowsUpdateDownloadOverMeteredNetworkSpecVerify()
			);

			#endregion

			return MUnit.CreateMUnitsFromPolicies(Categories.WindowsUpdateConfigurations);
		}, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// Gets the current catalog of all MUnits for this ViewModel.
	/// </summary>
	public override List<MUnit> AllMUnits => LazyCatalog.Value;

	/// <summary>
	/// Specialized verification for AllowAutoWindowsUpdateDownloadOverMeteredNetwork.
	/// </summary>
	private sealed class AllowAutoWindowsUpdateDownloadOverMeteredNetworkSpecVerify : ISpecializedVerificationStrategy
	{
		public bool Verify()
		{
			try
			{
				string result = QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, "get root\\cimv2\\mdm\\dmmap MDM_Policy_Result01_Update02 AllowAutoWindowsUpdateDownloadOverMeteredNetwork");

				return string.Equals(result, "1", StringComparison.OrdinalIgnoreCase);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return false;
			}
		}
	}
}

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
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using AppControlManager.Others;

namespace AppControlManager.ViewModels;

internal sealed partial class CodeIntegrityInfoVM : ViewModelBase
{

	#region UI-Bound Properties

	internal string? UMCI { get; set => SP(ref field, value); }

	internal string? KMCI { get; set => SP(ref field, value); }

	internal ObservableCollection<CodeIntegrityOption> codeIntegrityOptions = [];

	#endregion


	/// <summary>
	/// Local method to convert numbers to their actual string values
	/// </summary>
	/// <param name="status"></param>
	/// <returns></returns>
	private static string? GetPolicyStatus(int? status) => status switch
	{
		0 => GlobalVars.Rizz.GetString("NotRunningOrDisabled"),
		1 => GlobalVars.Rizz.GetString("AuditMode"),
		2 => GlobalVars.Rizz.GetString("EnforcedMode"),
		_ => null
	};

	/// <summary>
	/// Event handler for the retrieve code integrity information button
	/// </summary>
	internal async void RetrieveCodeIntegrityInfo_Click()
	{
		// Get the system code integrity information
		SystemCodeIntegrityInfo codeIntegrityInfoResult = await Task.Run(DetailsRetrieval.Get);

		codeIntegrityOptions.Clear();

		foreach (CodeIntegrityOption item in codeIntegrityInfoResult.CodeIntegrityDetails)
		{
			codeIntegrityOptions.Add(item);
		}

		UMCI = null;
		KMCI = null;

		// Get the Application Control Status
		DeviceGuardInteropClass? DGStatus = await Task.Run(DeviceGuardInfo.GetDeviceGuardStatus);

		UMCI = GetPolicyStatus(DGStatus.UsermodeCodeIntegrityPolicyEnforcementStatus);
		KMCI = GetPolicyStatus(DGStatus.CodeIntegrityPolicyEnforcementStatus);
	}

}

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
using System.Collections.ObjectModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using CommonCore.IntelGathering;

namespace AppControlManager.ViewModels;

internal sealed partial class CodeIntegrityInfoVM : ViewModelBase
{
	internal readonly InfoBarSettings MainInfoBar = new();

	internal string? UMCI { get; set => SP(ref field, value); }

	internal string? KMCI { get; set => SP(ref field, value); }

	internal ObservableCollection<CodeIntegrityOption> codeIntegrityOptions = [];

	/// <summary>
	/// Local method to convert numbers to their actual string values
	/// </summary>
	/// <param name="status"></param>
	/// <returns></returns>
	private static string? GetPolicyStatus(object? status) => status switch
	{
		0L => Atlas.GetStr("NotRunningOrDisabled"),
		1L => Atlas.GetStr("AuditMode"),
		2L => Atlas.GetStr("EnforcedMode"),
		_ => null
	};

	/// <summary>
	/// Event handler for the retrieve code integrity information button
	/// </summary>
	internal async void RetrieveCodeIntegrityInfo_Click()
	{
		try
		{
			// Get the system code integrity information
			SystemCodeIntegrityInfo codeIntegrityInfoResult = await Task.Run(DetailsRetrieval.Get);

			codeIntegrityOptions.Clear();

			foreach (CodeIntegrityOption item in CollectionsMarshal.AsSpan(codeIntegrityInfoResult.CodeIntegrityDetails))
			{
				codeIntegrityOptions.Add(item);
			}

			const string command = @"get root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard";

			// Get the Application Control Status
			await Task.Run(async () =>
			{
				string result = ProcessStarter.RunCommand(Atlas.ComManagerProcessPath, command) ?? throw new InvalidOperationException($"No output were returned from {Atlas.ComManagerProcessPath}");
				List<Dictionary<string, object?>> deserializedData = ComJsonDeserializer.DeserializeInstances(result);
				Dictionary<string, object?>? processedData = deserializedData.FirstOrDefault();
				if (processedData is not null)
				{
					UMCI = GetPolicyStatus(processedData["UsermodeCodeIntegrityPolicyEnforcementStatus"]);
					KMCI = GetPolicyStatus(processedData["CodeIntegrityPolicyEnforcementStatus"]);
				}
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

}

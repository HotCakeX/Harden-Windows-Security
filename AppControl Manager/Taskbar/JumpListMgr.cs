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

using System.Threading.Tasks;
using Windows.UI.StartScreen;

namespace AppControlManager.Taskbar;

/// <summary>
/// https://learn.microsoft.com/uwp/api/windows.ui.startscreen.jumplistitem
/// </summary>
internal static class JumpListMgr
{
	internal static async Task RegisterJumpListTasksAsync()
	{
		if (!JumpList.IsSupported())
		{
			Logger.Write(GlobalVars.GetStr("JumpListNotSupportedMessage"));
			return;
		}

		JumpList jumpList = await JumpList.LoadCurrentAsync();
		jumpList.Items.Clear();

		// Defining the task entries

		JumpListItem OpenPolicyEditor = JumpListItem.CreateWithArguments("task=Deploy-MS-KMCI-Block-Rules", "Deploy Latest Kernel-Mode Blocklist");
		OpenPolicyEditor.Description = "Deploys the latest Microsoft Recommended Drivers Blocklist on the system, replacing any existing non-system one.";
		jumpList.Items.Add(OpenPolicyEditor);

		// Apply it
		await jumpList.SaveAsync();
	}
}

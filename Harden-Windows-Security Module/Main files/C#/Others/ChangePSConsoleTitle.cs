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

namespace HardenWindowsSecurity;

public static class ChangePSConsoleTitle
{
	/// <summary>
	/// Attempts to set the title of the PowerShell console if it exists
	/// Doesn't throw any errors if for some reason this low priority task fails
	/// </summary>
	/// <param name="Title">The string to set as the title of the PowerShell Console</param>
	public static void Set(string Title)
	{
		if (GlobalVars.Host is not null)
		{
			try
			{
				GlobalVars.Host.UI.RawUI.WindowTitle = Title;
			}
			catch { }
		}
	}
}

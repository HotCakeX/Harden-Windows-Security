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

using Microsoft.UI.Xaml.Controls;

namespace CommonCore.Others;

/// <summary>
/// ViewModels initialize this in their ctor and XAML pages directly bind to the properties available in each instance.
/// </summary>
internal sealed partial class InfoBarSettings : ViewModelBase
{
	internal InfoBarSeverity Severity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool IsOpen { get; set => SP(ref field, value); }
	internal bool IsClosable { get; set => SP(ref field, value); } = true;
	internal string? Message { get; set => SP(ref field, value); }
	internal string? Title { get; set => SP(ref field, value); }

	internal void WriteInfo(string Msg, string? title = null)
	{
		if (Atlas.AppDispatcher.HasThreadAccess)
		{
			IsOpen = true;
			Message = Msg;
			Title = title ?? Atlas.GetStr("Status");
			Severity = InfoBarSeverity.Informational;
			IsClosable = false;
		}
		else
		{
			_ = Atlas.AppDispatcher.TryEnqueue(() =>
			{
				IsOpen = true;
				Message = Msg;
				Title = title ?? Atlas.GetStr("Status");
				Severity = InfoBarSeverity.Informational;
				IsClosable = false;
			});
		}
		Logger.Write(title is not null ? CreateProperString(title) + Msg : Msg);
	}

	internal void WriteWarning(string Msg, string? title = null)
	{
		if (Atlas.AppDispatcher.HasThreadAccess)
		{
			IsOpen = true;
			Message = Msg;
			Title = title ?? Atlas.GetStr("WarningTitle");
			Severity = InfoBarSeverity.Warning;
			IsClosable = true;
		}
		else
		{
			_ = Atlas.AppDispatcher.TryEnqueue(() =>
			{
				IsOpen = true;
				Message = Msg;
				Title = title ?? Atlas.GetStr("WarningTitle");
				Severity = InfoBarSeverity.Warning;
				IsClosable = true;
			});
		}

		Logger.Write(title is not null ? CreateProperString(title) + Msg : Msg);
	}

	internal void WriteError(Exception ex, string? Msg = null, string? title = null)
	{
		if (Atlas.AppDispatcher.HasThreadAccess)
		{
			IsOpen = true;
			Message = Msg is not null ? CreateProperString(Msg) + ex.Message : ex.Message;
			Title = title ?? Atlas.GetStr("ErrorTitle");
			Severity = InfoBarSeverity.Error;
			IsClosable = true;
		}
		else
		{
			_ = Atlas.AppDispatcher.TryEnqueue(() =>
			{
				IsOpen = true;
				Message = Msg is not null ? CreateProperString(Msg) + ex.Message : ex.Message;
				Title = title ?? Atlas.GetStr("ErrorTitle");
				Severity = InfoBarSeverity.Error;
				IsClosable = true;
			});
		}
		Logger.Write(ex);
	}

	internal void WriteSuccess(string Msg, string? title = null)
	{
		if (Atlas.AppDispatcher.HasThreadAccess)
		{
			IsOpen = true;
			Message = Msg;
			Title = title ?? Atlas.GetStr("SuccessText");
			Severity = InfoBarSeverity.Success;
			IsClosable = true;
		}
		else
		{
			_ = Atlas.AppDispatcher.TryEnqueue(() =>
			{
				IsOpen = true;
				Message = Msg;
				Title = title ?? Atlas.GetStr("SuccessText");
				Severity = InfoBarSeverity.Success;
				IsClosable = true;
			});
		}
		Logger.Write(title is not null ? CreateProperString(title) + Msg : Msg);
	}

	private static readonly char[] CharsToTrim = [' ', ':', '.'];

	/// <summary>
	/// Make sure all compound strings end with ": " which form the first part of a message.
	/// </summary>
	/// <param name="str"></param>
	/// <returns></returns>
	private static string CreateProperString(string str) => str.TrimEnd(CharsToTrim) + ": ";

}

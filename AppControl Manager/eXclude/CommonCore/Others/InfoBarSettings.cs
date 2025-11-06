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

using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;

namespace CommonCore.Others;

/// <summary>
/// Used to pass ViewModel based properties of an InfoBar element to a class constructor
/// in a way that the receiver will be able to modify the original objects.
/// </summary>
/// <param name="getIsOpen"></param>
/// <param name="setIsOpen"></param>
/// <param name="getMessage"></param>
/// <param name="setMessage"></param>
/// <param name="getSeverity"></param>
/// <param name="setSeverity"></param>
/// <param name="getIsClosable"></param>
/// <param name="setIsClosable"></param>
/// <param name="getTitle"></param>
/// <param name="setTitle"></param>
internal sealed class InfoBarSettings(
	Func<bool> getIsOpen, Action<bool> setIsOpen,
	Func<string?> getMessage, Action<string?> setMessage,
	Func<InfoBarSeverity> getSeverity, Action<InfoBarSeverity> setSeverity,
	Func<bool> getIsClosable, Action<bool> setIsClosable,
	DispatcherQueue DQ,
	Func<string?>? getTitle = null, Action<string?>? setTitle = null)
{
	internal bool IsOpen
	{
		get => getIsOpen();
		set => setIsOpen(value);
	}

	internal string? Message
	{
		get => getMessage();
		set => setMessage(value);
	}

	internal InfoBarSeverity Severity
	{
		get => getSeverity();
		set => setSeverity(value);
	}

	internal bool IsClosable
	{
		get => getIsClosable();
		set => setIsClosable(value);
	}

	internal string? Title
	{
		// call the delegate if non-null, otherwise no-op fallback:
		get => getTitle?.Invoke();
		set => (setTitle ?? (_ => { }))(value);
	}

	internal void WriteInfo(string Msg, string? title = null)
	{
		if (DQ.HasThreadAccess)
		{
			IsOpen = true;
			Message = Msg;
			Title = title ?? GlobalVars.GetStr("Status");
			Severity = InfoBarSeverity.Informational;
			IsClosable = false;
		}
		else
		{
			_ = DQ.TryEnqueue(() =>
			{
				IsOpen = true;
				Message = Msg;
				Title = title ?? GlobalVars.GetStr("Status");
				Severity = InfoBarSeverity.Informational;
				IsClosable = false;
			});
		}
		Logger.Write(title is not null ? CreateProperString(title) + Msg : Msg);
	}

	internal void WriteWarning(string Msg, string? title = null)
	{
		if (DQ.HasThreadAccess)
		{
			IsOpen = true;
			Message = Msg;
			Title = title ?? GlobalVars.GetStr("WarningTitle");
			Severity = InfoBarSeverity.Warning;
			IsClosable = true;
		}
		else
		{
			_ = DQ.TryEnqueue(() =>
			{
				IsOpen = true;
				Message = Msg;
				Title = title ?? GlobalVars.GetStr("WarningTitle");
				Severity = InfoBarSeverity.Warning;
				IsClosable = true;
			});
		}

		Logger.Write(title is not null ? CreateProperString(title) + Msg : Msg);
	}

	internal void WriteError(Exception ex, string? Msg = null, string? title = null)
	{
		if (DQ.HasThreadAccess)
		{
			IsOpen = true;
			Message = Msg is not null ? CreateProperString(Msg) + ex.Message : ex.Message;
			Title = title ?? GlobalVars.GetStr("ErrorTitle");
			Severity = InfoBarSeverity.Error;
			IsClosable = true;
		}
		else
		{
			_ = DQ.TryEnqueue(() =>
			{
				IsOpen = true;
				Message = Msg is not null ? CreateProperString(Msg) + ex.Message : ex.Message;
				Title = title ?? GlobalVars.GetStr("ErrorTitle");
				Severity = InfoBarSeverity.Error;
				IsClosable = true;
			});
		}
		Logger.Write(ex);
	}

	internal void WriteSuccess(string Msg, string? title = null)
	{
		if (DQ.HasThreadAccess)
		{
			IsOpen = true;
			Message = Msg;
			Title = title ?? GlobalVars.GetStr("SuccessText");
			Severity = InfoBarSeverity.Success;
			IsClosable = true;
		}
		else
		{
			_ = DQ.TryEnqueue(() =>
			{
				IsOpen = true;
				Message = Msg;
				Title = title ?? GlobalVars.GetStr("SuccessText");
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

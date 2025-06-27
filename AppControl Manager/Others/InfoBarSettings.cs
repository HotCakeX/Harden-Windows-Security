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
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.Others;

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
		IsOpen = true;
		Message = Msg;
		Title = title ?? GlobalVars.GetStr("Status");
		Logger.Write(title is not null ? title + ": " + Msg : Msg);
		Severity = InfoBarSeverity.Informational;
		IsClosable = false;
	}

	internal void WriteWarning(string Msg, string? title = null)
	{
		IsOpen = true;
		Message = Msg;
		Title = title ?? GlobalVars.GetStr("WarningTitle");
		Logger.Write(title is not null ? title + ": " + Msg : Msg);
		Severity = InfoBarSeverity.Warning;
		IsClosable = true;
	}

	internal void WriteError(Exception ex, string? Msg = null, string? title = null)
	{
		IsOpen = true;
		Message = Msg is not null ? Msg + ex.Message : ex.Message;
		Title = title ?? GlobalVars.GetStr("ErrorTitle");
		Logger.Write(ErrorWriter.FormatException(ex));
		Severity = InfoBarSeverity.Error;
		IsClosable = true;
	}

	internal void WriteSuccess(string Msg, string? title = null)
	{
		IsOpen = true;
		Message = Msg;
		Title = title ?? GlobalVars.GetStr("SuccessTitle");
		Logger.Write(title is not null ? title + ": " + Msg : Msg);
		Severity = InfoBarSeverity.Success;
		IsClosable = true;
	}
}

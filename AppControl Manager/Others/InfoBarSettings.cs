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
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.Others;

/// <summary>
/// Used to pass ViewModel based properties of an InfoBar element to a class constructor
/// in a way that the receiver will be able to modify the original objects.
/// </summary>
/// <param name="getVisibility"></param>
/// <param name="setVisibility"></param>
/// <param name="getIsOpen"></param>
/// <param name="setIsOpen"></param>
/// <param name="getMessage"></param>
/// <param name="setMessage"></param>
/// <param name="getSeverity"></param>
/// <param name="setSeverity"></param>
/// <param name="getIsClosable"></param>
/// <param name="setIsClosable"></param>
internal sealed class InfoBarSettings(
	Func<Visibility> getVisibility, Action<Visibility> setVisibility,
	Func<bool> getIsOpen, Action<bool> setIsOpen,
	Func<string?> getMessage, Action<string?> setMessage,
	Func<InfoBarSeverity> getSeverity, Action<InfoBarSeverity> setSeverity,
	Func<bool> getIsClosable, Action<bool> setIsClosable)
{
	private readonly Action<Visibility> _setVisibility = setVisibility;
	private readonly Func<Visibility> _getVisibility = getVisibility;

	private readonly Action<bool> _setIsOpen = setIsOpen;
	private readonly Func<bool> _getIsOpen = getIsOpen;

	private readonly Action<string?> _setMessage = setMessage;
	private readonly Func<string?> _getMessage = getMessage;

	private readonly Action<InfoBarSeverity> _setSeverity = setSeverity;
	private readonly Func<InfoBarSeverity> _getSeverity = getSeverity;

	private readonly Action<bool> _setIsClosable = setIsClosable;
	private readonly Func<bool> _getIsClosable = getIsClosable;

	internal Visibility Visibility
	{
		get => _getVisibility();
		set => _setVisibility(value);
	}

	internal bool IsOpen
	{
		get => _getIsOpen();
		set => _setIsOpen(value);
	}

	internal string? Message
	{
		get => _getMessage();
		set => _setMessage(value);
	}

	internal InfoBarSeverity Severity
	{
		get => _getSeverity();
		set => _setSeverity(value);
	}

	internal bool IsClosable
	{
		get => _getIsClosable();
		set => _setIsClosable(value);
	}
}

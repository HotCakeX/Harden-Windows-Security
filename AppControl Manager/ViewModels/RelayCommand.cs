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

using System.Windows.Input;

namespace AppControlManager.ViewModels;

internal sealed partial class RelayCommand : ICommand
{
	private readonly Action<object?> _execute;
	private readonly Func<object?, bool>? _canExecute;

	internal RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
	{
		_execute = execute ?? throw new ArgumentNullException(nameof(execute));
		_canExecute = canExecute;
	}

	public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;

	public void Execute(object? parameter) => _execute(parameter);

	public event EventHandler? CanExecuteChanged;
	internal void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

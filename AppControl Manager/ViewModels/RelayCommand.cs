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
using System.Windows.Input;

namespace AppControlManager.ViewModels;

// This is a partial class named RelayCommand that implements the ICommand interface.
// The class uses a primary constructor with parameters 'execute' and 'canExecute' to reduce boilerplate.
// The 'execute' parameter is an Action that contains the code to execute when the command is invoked.
// The optional 'canExecute' parameter is a Func<bool> that determines whether the command is enabled.
public partial class RelayCommand(Action execute, Func<bool>? canExecute = null) : ICommand
{
	// Event that must be raised whenever the result of CanExecute changes.
	// UI elements binding to this command subscribe to this event to know when to enable or disable themselves.
	public event EventHandler? CanExecuteChanged;

	// Implementation of the ICommand.CanExecute method.
	// It determines whether the command can be executed by checking the 'canExecute' delegate.
	// If 'canExecute' is null, the command is always executable.
	public bool CanExecute(object? parameter) => canExecute == null || canExecute();

	// Implementation of the ICommand.Execute method.
	// Invokes the 'execute' delegate to perform the command's action.
	public void Execute(object? parameter) => execute();

	// Helper method to raise the CanExecuteChanged event.
	// This notifies any bound controls that they should re-check the command's ability to execute.
	public void OnCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

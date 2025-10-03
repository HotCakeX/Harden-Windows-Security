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
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

internal sealed partial class SidebarVM : ViewModelBase
{

	internal Visibility SidebarBasePolicySelectButtonLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal Visibility SidebarPolicyConnect1Visibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility SidebarPolicyConnect2Visibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility SidebarPolicyConnect3Visibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility SidebarPolicyConnect4Visibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility SidebarPolicyConnect5Visibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility SidebarPolicyConnect6Visibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal string? SidebarPolicyConnect1Content { get; set => SP(ref field, value); }
	internal string? SidebarPolicyConnect2Content { get; set => SP(ref field, value); }
	internal string? SidebarPolicyConnect3Content { get; set => SP(ref field, value); }
	internal string? SidebarPolicyConnect4Content { get; set => SP(ref field, value); }
	internal string? SidebarPolicyConnect5Content { get; set => SP(ref field, value); }
	internal string? SidebarPolicyConnect6Content { get; set => SP(ref field, value); }

	internal ICommand? SidebarPolicyConnect1Command
	{
		get; set
		{
			if (SP(ref field, value))
			{
				SidebarPolicyConnect1Visibility = field is not null ? Visibility.Visible : Visibility.Collapsed;
			}
		}
	}

	internal ICommand? SidebarPolicyConnect2Command
	{
		get; set
		{
			if (SP(ref field, value))
			{
				SidebarPolicyConnect2Visibility = field is not null ? Visibility.Visible : Visibility.Collapsed;
			}
		}
	}

	internal ICommand? SidebarPolicyConnect3Command
	{
		get; set
		{
			if (SP(ref field, value))
			{
				SidebarPolicyConnect3Visibility = field is not null ? Visibility.Visible : Visibility.Collapsed;
			}
		}
	}

	internal ICommand? SidebarPolicyConnect4Command
	{
		get; set
		{
			if (SP(ref field, value))
			{
				SidebarPolicyConnect4Visibility = field is not null ? Visibility.Visible : Visibility.Collapsed;
			}
		}
	}

	internal ICommand? SidebarPolicyConnect5Command
	{
		get; set
		{
			if (SP(ref field, value))
			{
				SidebarPolicyConnect5Visibility = field is not null ? Visibility.Visible : Visibility.Collapsed;
			}
		}
	}

	internal ICommand? SidebarPolicyConnect6Command
	{
		get; set
		{
			if (SP(ref field, value))
			{
				SidebarPolicyConnect6Visibility = field is not null ? Visibility.Visible : Visibility.Collapsed;
			}
		}
	}

	internal void Nullify()
	{
		SidebarPolicyConnect1Command = null;
		SidebarPolicyConnect1Content = null;
		SidebarPolicyConnect2Command = null;
		SidebarPolicyConnect2Content = null;
		SidebarPolicyConnect3Command = null;
		SidebarPolicyConnect3Content = null;
		SidebarPolicyConnect4Command = null;
		SidebarPolicyConnect4Content = null;
		SidebarPolicyConnect5Command = null;
		SidebarPolicyConnect5Content = null;
		SidebarPolicyConnect6Command = null;
		SidebarPolicyConnect6Content = null;
	}

	internal void AssignActionPacks(
			(Action<object?>, string)? actionPack1 = null,
			(Action<object?>, string)? actionPack2 = null,
			(Action<object?>, string)? actionPack3 = null,
			(Action<object?>, string)? actionPack4 = null,
			(Action<object?>, string)? actionPack5 = null,
			(Action<object?>, string)? actionPack6 = null)
	{
		if (actionPack1 is not null)
		{
			SidebarPolicyConnect1Command = new RelayCommand(actionPack1.Value.Item1);
			SidebarPolicyConnect1Content = actionPack1.Value.Item2;
		}
		if (actionPack2 is not null)
		{
			SidebarPolicyConnect2Command = new RelayCommand(actionPack2.Value.Item1);
			SidebarPolicyConnect2Content = actionPack2.Value.Item2;
		}
		if (actionPack3 is not null)
		{
			SidebarPolicyConnect3Command = new RelayCommand(actionPack3.Value.Item1);
			SidebarPolicyConnect3Content = actionPack3.Value.Item2;
		}
		if (actionPack4 is not null)
		{
			SidebarPolicyConnect4Command = new RelayCommand(actionPack4.Value.Item1);
			SidebarPolicyConnect4Content = actionPack4.Value.Item2;
		}
		if (actionPack5 is not null)
		{
			SidebarPolicyConnect5Command = new RelayCommand(actionPack5.Value.Item1);
			SidebarPolicyConnect5Content = actionPack5.Value.Item2;
		}
		if (actionPack6 is not null)
		{
			SidebarPolicyConnect6Command = new RelayCommand(actionPack6.Value.Item1);
			SidebarPolicyConnect6Content = actionPack6.Value.Item2;
		}
	}

}

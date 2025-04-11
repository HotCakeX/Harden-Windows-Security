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

using System.IO;
using System.Windows;
using System.Windows.Controls;

namespace HardenWindowsSecurity;

/// <summary>
/// The following are XAML GUI Elements
/// </summary>
public partial class GUIMain
{
	// Define the path to the main Window XAML file
	internal static readonly string xamlPath = Path.Combine(GlobalVars.path, "Resources", "XAML", "Main.xaml");

	// Main window instance
	public static Window? mainGUIWindow;

	// Application instance
	// Create and initialize the application - the WPF GUI uses the App context
	public static readonly Application app = new();

	// The main progress bar for the entire GUI
	internal static ProgressBar? mainProgressBar;
}

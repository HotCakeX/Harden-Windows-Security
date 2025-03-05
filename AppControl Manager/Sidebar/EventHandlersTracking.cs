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

using Microsoft.UI.Xaml;

namespace AppControlManager.Sidebar;

/// <summary>
/// Each page that implements the IAnimatedIconsManager interface assigns local event handlers to the sidebar buttons
/// And after method assignment, sets the same method to one of the static variables defined in this class so the main Window class
/// Will use it for un-subscription
/// </summary>
internal static class EventHandlersTracking
{
	internal static RoutedEventHandler? SidebarUnsignedBasePolicyConnect1EventHandler;
	internal static RoutedEventHandler? SidebarUnsignedBasePolicyConnect2EventHandler;
	internal static RoutedEventHandler? SidebarUnsignedBasePolicyConnect3EventHandler;
	internal static RoutedEventHandler? SidebarUnsignedBasePolicyConnect4EventHandler;
	internal static RoutedEventHandler? SidebarUnsignedBasePolicyConnect5EventHandler;
}

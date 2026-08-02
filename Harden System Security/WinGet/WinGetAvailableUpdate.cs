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

namespace HardenSystemSecurity.WinGet;

/// <summary>
/// A single installed package that WinGet reports an available update for.
///
/// It is an immutable plain object on purpose, unlike <see cref="WinGetPackageSearchResult"/> which is a
/// <see cref="ViewModelBase"/> and therefore requires the XAML dispatcher of the app to raise its change notifications.
/// That makes this type usable from processes of the app that never start the XAML application, such as the headless
/// widget provider COM server.
/// </summary>
/// <param name="id">The WinGet package identifier.</param>
/// <param name="name">The display name of the package.</param>
/// <param name="installedVersion">The version that is currently installed.</param>
/// <param name="availableVersion">The version that WinGet offers as the update.</param>
internal sealed class WinGetAvailableUpdate(string id, string name, string installedVersion, string availableVersion)
{
	internal string Id => id;
	internal string Name => name;
	internal string InstalledVersion => installedVersion;
	internal string AvailableVersion => availableVersion;
}

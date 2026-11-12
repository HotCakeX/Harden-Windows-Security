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

using System.ComponentModel;
using AppControlManager.CustomUIElements;

namespace HardenSystemSecurity.DNS;

/// <summary>
/// Asks for the details of a custom upstream DNS over HTTPS resolver of the DNS page.
/// </summary>
internal sealed partial class AddDohResolverDialog : ContentDialogV2, INPCImplant
{
	private CommonCore.AppSettings.Main AppSettings => Atlas.Settings;

	internal AddDohResolverDialog() => InitializeComponent();

	/// <summary>
	/// The company that operates the resolver.
	/// </summary>
	internal string Company
	{
		get; set
		{
			if (this.SP(ref field, value))
			{
				UpdateValidity();
			}
		}
	} = string.Empty;

	/// <summary>
	/// The HTTPS address of the resolver.
	/// </summary>
	internal string ResolverUri
	{
		get; set
		{
			if (this.SP(ref field, value))
			{
				UpdateValidity();
			}
		}
	} = string.Empty;

	/// <summary>
	/// A short description of the resolver.
	/// </summary>
	internal string Description
	{
		get; set
		{
			if (this.SP(ref field, value))
			{
				UpdateValidity();
			}
		}
	} = string.Empty;

	/// <summary>
	/// Whether the entered details describe a usable resolver. The Add button is only enabled when they do.
	/// </summary>
	internal bool IsValid { get; private set => this.SP(ref field, value); }

	private void UpdateValidity() => IsValid = IsValidResolver(Company.Trim(), ResolverUri.Trim(), Description.Trim());

	/// <summary>
	/// Whether the company and the description are filled in and the address is an absolute HTTPS URL.
	/// </summary>
	internal static bool IsValidResolver(string company, string uriText, string description) =>
		company.Length != 0 &&
		description.Length != 0 &&
		Uri.TryCreate(uriText, UriKind.Absolute, out Uri? uri) &&
		string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

	#region IPropertyChangeHost Implementation
	public event PropertyChangedEventHandler? PropertyChanged;
	public void RaisePropertyChanged(string? propertyName) => PropertyChanged?.Invoke(this, new(propertyName));
	#endregion

}

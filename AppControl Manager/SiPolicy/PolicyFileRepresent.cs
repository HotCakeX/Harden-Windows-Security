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
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.XMLOps;
using Windows.System;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml;
using System.Text.Json.Serialization;
using System.Collections.Generic;

namespace AppControlManager.SiPolicy;

/// <summary>
/// This type represents a <see cref="SiPolicy.SiPolicy"/> object for representation in different parts of the app and UI.
/// </summary>
/// <param name="policyObj"></param>
internal sealed partial class PolicyFileRepresent(SiPolicy policyObj, PolicyFileRepresentKind kind = PolicyFileRepresentKind.XML) : ViewModelBase
{
	/// <summary>
	/// The main policy object.
	/// </summary>
	internal SiPolicy PolicyObj
	{
		get; set
		{
			field = value;
			PolicyIdentifier = GetIdentifier(field);
		}
	} = policyObj;

	internal PolicyFileRepresentKind Kind => kind;

	/// <summary>
	/// An identifier for the policy. Includes the policy name (if available) or the policy ID.
	/// Used for displaying purposes on the UI.
	/// </summary>
	internal string PolicyIdentifier { get; private set => SP(ref field, value); } = GetIdentifier(policyObj);

	/// <summary>
	/// The path of the file from which the policy was loaded, if applicable.
	/// Not always present and only used for certain areas.
	/// </summary>
	internal string? FilePath { get; set; }

	/// <summary>
	/// The name of the file from which the policy was loaded, if applicable.
	/// Not always present and only used for certain areas.
	/// </summary>
	internal string? FileName { get; set; }

	/// <summary>
	/// The brush used to display the policy color tag indicator.
	/// </summary>
	internal SolidColorBrush? TagColorBrush { get; set => SP(ref field, value); }

	/// <summary>
	/// The visibility of the policy color tag indicator.
	/// </summary>
	internal Visibility IsTagVisible { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Helper method to generate the identifier string.
	/// </summary>
	/// <param name="policy"></param>
	/// <returns></returns>
	private static string GetIdentifier(SiPolicy policy) => PolicySettingsManager.GetPolicyName(policy) ?? policy.PolicyID;

	/// <summary>
	/// The ID of the policy.
	/// </summary>
	internal string PolicyID => PolicyObj.PolicyID;

	/// <summary>
	/// A unique ID to identify this object instance so that even if everything about the policy changes such as name, ID etc.
	/// We will still be able to identify it in the policies library.
	/// Settable so that we can override it during persistent library restoration.
	/// </summary>
	internal Guid UniqueObjID { get; set; } = Guid.CreateVersion7();

	/// <summary>
	/// Determines whether the policy is Signed or Unsigned.
	/// </summary>
	internal string SigningStatus => PolicyObj.Rules.Any(x => x.Item == OptionType.EnabledUnsignedSystemIntegrityPolicy) ? Atlas.GetStr("Unsigned") : Atlas.GetStr("Signed");

	/// <summary>
	/// This is required so ListBox can show the string representation directly for displaying purposes.
	/// </summary>
	/// <returns></returns>
	public override string ToString() => PolicyIdentifier;

	/// <summary>
	/// Accepts a policy file representation, offers a save dialog so user can save it somewhere,
	/// Then opens the file in the default file handler in the OS.
	/// </summary>
	/// <param name="policy"></param>
	internal static async Task OpenInDefaultFileHandler(PolicyFileRepresent? policy)
	{
		try
		{
			if (policy is null) return;

			string? savePath = Path.Exists(policy.FilePath) ? policy.FilePath : await MainWindow.ExecuteSaveAsXML(policy);

			if (savePath is not null)
				_ = await Launcher.LaunchUriAsync(new(savePath));
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}
}

internal enum PolicyFileRepresentKind
{
	XML = 0,
	CIP,
	P7B,
	BIN
}

/// <summary>
/// Source generator context for JSON serialization and deserialization of the Policies Library color tags.
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(Dictionary<Guid, string>))]
internal sealed partial class PolicyColorsJsonContext : JsonSerializerContext
{
}

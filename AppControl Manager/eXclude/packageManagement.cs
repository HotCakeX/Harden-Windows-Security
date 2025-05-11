using System;
using System.Collections.Generic;
using Windows.ApplicationModel;

namespace AppControlManager.Others;

public class PackageDetails
{
	// General Information
	public string? DisplayName { get; set; }
	public string? PublisherDisplayName { get; set; }
	public string? Description { get; set; }
	public Uri? Logo { get; set; }

	// Package Identity Information
	public string? Id_Name { get; set; }
	public string? Id_FullName { get; set; }
	public string? Id_FamilyName { get; set; }
	public string? Id_Publisher { get; set; }
	public string? Id_PublisherId { get; set; }
	public string? Id_ResourceId { get; set; }
	public string? Id_Architecture { get; set; }
	public string? Id_Version { get; set; }

	// Storage and Installation Information
	public bool IsFramework { get; set; }
	public bool IsResourcePackage { get; set; }
	public bool IsBundle { get; set; }
	public bool IsDevelopmentMode { get; set; }
	public string? EffectiveDate { get; set; }

	// Dependencies
	public IEnumerable<string>? Dependencies { get; set; }

	// Static Method to Create PackageDetails from Package
	public static PackageDetails FromPackage(Package package)
	{
		// Helper method to handle property access safely
		string? SafeGet(Func<string> accessor, string? defaultValue = null)
		{
			try { return accessor(); } catch { return defaultValue; }
		}

		Uri? SafeGetUri(Func<Uri> accessor, Uri? defaultValue = null)
		{
			try { return accessor(); } catch { return defaultValue; }
		}

		bool SafeGetBool(Func<bool> accessor, bool defaultValue = false)
		{
			try { return accessor(); } catch { return defaultValue; }
		}

		return new PackageDetails
		{
			// General Information
			DisplayName = SafeGet(() => package.DisplayName),
			PublisherDisplayName = SafeGet(() => package.PublisherDisplayName),
			Description = SafeGet(() => package.Description),
			Logo = SafeGetUri(() => package.Logo),

			// Package Identity Information
			Id_Name = SafeGet(() => package.Id.Name),
			Id_FullName = SafeGet(() => package.Id.FullName),
			Id_FamilyName = SafeGet(() => package.Id.FamilyName),
			Id_Publisher = SafeGet(() => package.Id.Publisher),
			Id_PublisherId = SafeGet(() => package.Id.PublisherId),
			Id_ResourceId = SafeGet(() => package.Id.ResourceId),
			Id_Architecture = SafeGet(package.Id.Architecture.ToString),
			Id_Version = SafeGet(() => $"{package.Id.Version.Major}.{package.Id.Version.Minor}.{package.Id.Version.Build}.{package.Id.Version.Revision}"),

			// Storage and Installation Information
			IsFramework = SafeGetBool(() => package.IsFramework),
			IsResourcePackage = SafeGetBool(() => package.IsResourcePackage),
			IsBundle = SafeGetBool(() => package.IsBundle),
			IsDevelopmentMode = SafeGetBool(() => package.IsDevelopmentMode),
			EffectiveDate = SafeGet(() => package.InstalledDate.ToString("o")),

			// Dependencies
			Dependencies = GetDependencyFullNames(package.Dependencies)
		};
	}

	private static IEnumerable<string> GetDependencyFullNames(IReadOnlyList<Package> dependencies)
	{
		foreach (Package dependency in dependencies)
		{
			yield return dependency.Id.FullName;
		}
	}
}

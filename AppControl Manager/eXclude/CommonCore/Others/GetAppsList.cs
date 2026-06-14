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

using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.IO.Enumeration;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Windows.ApplicationModel;
using Windows.Management.Core;
using Windows.Management.Deployment;

namespace CommonCore.Others;

internal static class GetAppsList
{
	private readonly record struct PackagedAppStorageDetails(long? AppSizeInBytes, long? AppDataSizeInBytes)
	{
		internal long? TotalUsageInBytes => AppSizeInBytes.HasValue && AppDataSizeInBytes.HasValue ? checked(AppSizeInBytes.Value + AppDataSizeInBytes.Value) : null;
	}

	private readonly record struct PackagedAppManifestDetails(string Capabilities, int CapabilityCount);

	// Package Manager object used by the PFN section
	private static readonly PackageManager packageManager = new();

	internal static readonly ConcurrentDictionary<string, string> SIDToNameDictionary = new(StringComparer.Ordinal);

	#region Image size detection

	/// <summary>
	/// Gets image dimensions from file header without loading the entire image
	/// Supports PNG, JPEG, BMP, GIF, and ICO formats
	/// </summary>
	/// <param name="filePath">Path to the image file</param>
	/// <returns>Tuple containing width and height, or (0,0) if unable to read</returns>
	private static (int width, int height) GetImageDimensions(string filePath)
	{
		if (filePath is not { Length: > 0 } || !File.Exists(filePath))
			return (0, 0);

		try
		{
			using FileStream stream = new(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
			using BinaryReader reader = new(stream);

			// Read first few bytes to determine file type
			Span<byte> header = stackalloc byte[8];
			int bytesRead = stream.Read(header);
			_ = stream.Seek(0, SeekOrigin.Begin);

			// PNG signature: 89 50 4E 47 0D 0A 1A 0A
			if (bytesRead >= 8 && header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47)
			{
				return ReadPngDimensions(reader);
			}
			// JPEG signature: FF D8 FF
			else if (bytesRead >= 3 && header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF)
			{
				return ReadJpegDimensions(reader);
			}
			// BMP signature: 42 4D
			else if (bytesRead >= 2 && header[0] == 0x42 && header[1] == 0x4D)
			{
				return ReadBmpDimensions(reader);
			}
			// GIF signature: 47 49 46 38
			else if (bytesRead >= 4 && header[0] == 0x47 && header[1] == 0x49 && header[2] == 0x46 && header[3] == 0x38)
			{
				return ReadGifDimensions(reader);
			}
			// ICO signature: 00 00 01 00
			else if (bytesRead >= 4 && header[0] == 0x00 && header[1] == 0x00 && header[2] == 0x01 && header[3] == 0x00)
			{
				return ReadIcoDimensions(reader);
			}

			return (0, 0);
		}
		catch
		{
			return (0, 0);
		}
	}

	/// <summary>
	/// Reads PNG image dimensions from header
	/// </summary>
	private static (int width, int height) ReadPngDimensions(BinaryReader reader)
	{
		// Skip PNG signature and IHDR chunk header
		_ = reader.BaseStream.Seek(16, SeekOrigin.Begin);
		return (ReadBigEndianInt32(reader), ReadBigEndianInt32(reader));
	}

	/// <summary>
	/// Reads JPEG image dimensions from header
	/// </summary>
	private static (int width, int height) ReadJpegDimensions(BinaryReader reader)
	{
		_ = reader.BaseStream.Seek(2, SeekOrigin.Begin); // Skip FF D8

		while (reader.BaseStream.Position < reader.BaseStream.Length - 1)
		{
			byte marker1 = reader.ReadByte();
			byte marker2 = reader.ReadByte();

			if (marker1 != 0xFF) continue;

			// SOF0, SOF1, SOF2 markers
			if (marker2 == 0xC0 || marker2 == 0xC1 || marker2 == 0xC2)
			{
				_ = reader.ReadUInt16(); // Skip length
				_ = reader.ReadByte();   // Skip precision
				int height = (reader.ReadByte() << 8) | reader.ReadByte();
				int width = (reader.ReadByte() << 8) | reader.ReadByte();
				return (width, height);
			}

			// Skip this segment
			int length = (reader.ReadByte() << 8) | reader.ReadByte();
			_ = reader.BaseStream.Seek(length - 2, SeekOrigin.Current);
		}

		return (0, 0);
	}

	/// <summary>
	/// Reads BMP image dimensions from header
	/// </summary>
	private static (int width, int height) ReadBmpDimensions(BinaryReader reader)
	{
		_ = reader.BaseStream.Seek(18, SeekOrigin.Begin); // Skip BMP header to width/height
		int width = reader.ReadInt32();
		int height = reader.ReadInt32();
		return (width, Math.Abs(height)); // Height can be negative in BMP
	}

	/// <summary>
	/// Reads GIF image dimensions from header
	/// </summary>
	private static (int width, int height) ReadGifDimensions(BinaryReader reader)
	{
		_ = reader.BaseStream.Seek(6, SeekOrigin.Begin); // Skip GIF signature
		int width = reader.ReadUInt16();
		int height = reader.ReadUInt16();
		return (width, height);
	}

	/// <summary>
	/// Reads ICO image dimensions from header (first icon)
	/// </summary>
	private static (int width, int height) ReadIcoDimensions(BinaryReader reader)
	{
		_ = reader.BaseStream.Seek(4, SeekOrigin.Begin); // Skip ICO signature
		ushort numImages = reader.ReadUInt16();

		if (numImages == 0) return (0, 0);

		// Read first icon entry
		byte width = reader.ReadByte();
		byte height = reader.ReadByte();

		// 0 means 256 pixels
		int actualWidth = width == 0 ? 256 : width;
		int actualHeight = height == 0 ? 256 : height;

		return (actualWidth, actualHeight);
	}

	/// <summary>
	/// Reads a big-endian 32-bit integer.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int ReadBigEndianInt32(BinaryReader reader)
	{
		Span<byte> bytes = stackalloc byte[sizeof(int)];
		reader.BaseStream.ReadExactly(bytes);
		return BinaryPrimitives.ReadInt32BigEndian(bytes);
	}

	/// <summary>
	/// Checks if the logo image meets the minimum size requirements (10x10 pixels)
	/// </summary>
	/// <param name="logoUri">The URI of the logo to check</param>
	/// <returns>True if the logo meets size requirements, false otherwise</returns>
	private static bool IsLogoSizeValid(string logoUri)
	{
		try
		{
			// Convert ms-appx URI to local file path if needed
			string filePath = logoUri;
			if (logoUri.StartsWith("ms-appx://", StringComparison.OrdinalIgnoreCase))
			{
				// For ms-appx URIs, we'll skip size validation as it's complex to resolve synchronously
				return true; // Assume valid to avoid blocking, since these are usually system-provided icons
			}

			// For file:// URIs, convert to local path
			if (logoUri.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
			{
				Uri uri = new(logoUri);
				filePath = uri.LocalPath;
			}

			if (!File.Exists(filePath))
			{
				return false;
			}

			(int width, int height) = GetImageDimensions(filePath);

			// Check if width or height is less than 10 pixels
			return width >= 10 && height >= 10;
		}
		catch (Exception ex)
		{
#if DEBUG
			Logger.Write(ex);
#endif
#if !DEBUG
			_ = ex;
#endif
			return false;
		}
	}

	#endregion

	/// <summary>
	/// Gets the list of all installed Packaged Apps
	/// </summary>
	/// <returns></returns>
	private static async Task<List<PackagedAppView>> Get(object? VVMRef = null)
	{
		return await Task.Run(() =>
		{
			// The list to return as output
			List<PackagedAppView> apps = [];
			string deferredSizeText = Atlas.GetStr("UnavailableOrUnknown");
			string notApplicableText = Atlas.GetStr("NAText");

			// Get all of the packages on the system if running elevated, otherwise get packages for the current user only.
			IEnumerable<Package> allApps = Atlas.IsElevated ? packageManager.FindPackages() : packageManager.FindPackagesForUser(string.Empty);

			// Loop over each package
			foreach (Package item in allApps)
			{
				try
				{
					PackagedAppManifestDetails manifestDetails = GetPackageManifestDetails(item);
					Windows.ApplicationModel.PackageStatus packageStatus = item.Status;
					PackageId packageId = item.Id;

					// Try get the logo string
					string? logoStr = item.Logo?.ToString();

					// Validate that the logo string is a valid absolute URI and check size requirements
					// Many logos exist and are valid URI but are 1x1 pixels which makes them useless to show on the ListView.
					if (!Uri.TryCreate(logoStr, UriKind.Absolute, out _) ||
						!IsLogoSizeValid(logoStr))
					{
						// If invalid URI or size is less than 10x10, assign a fallback logo
						logoStr = Atlas.FallBackAppLogoURI;
					}

					// Create a new instance of the class that displays each app in the ListView
					apps.Add(new PackagedAppView(
						displayName: item.DisplayName,
						version: FormatPackageVersion(packageId.Version),
						packageFamilyName: packageId.FamilyName,
						logo: logoStr,
						publisher: item.PublisherDisplayName,
						architecture: packageId.Architecture.ToString(),
						publisherID: packageId.PublisherId,
						fullName: packageId.FullName,
						description: string.IsNullOrEmpty(item.Description) ? "N/A" : item.Description,
						installLocation: GetInstallLocation(item),
						installedDate: item.InstalledDate.ToLocalTime().ToString(CultureInfo.CurrentCulture),
						isFramework: item.IsFramework ? bool.TrueString : bool.FalseString,
						packageUserInformation: GetPackageUserInformation(item),
						appSize: deferredSizeText,
						appDataSize: deferredSizeText,
						totalUsage: deferredSizeText,
						isResourcePackage: item.IsResourcePackage ? bool.TrueString : bool.FalseString,
						isBundle: item.IsBundle ? bool.TrueString : bool.FalseString,
						isDevelopmentMode: item.IsDevelopmentMode ? bool.TrueString : bool.FalseString,
						nonRemovable: GetPackageNonRemovable(item) is bool nonRemovableValue ? (nonRemovableValue ? bool.TrueString : bool.FalseString) : notApplicableText,
						dependencies: FormatPackageDependencies(item),
						isPartiallyStaged: packageStatus.IsPartiallyStaged ? bool.TrueString : bool.FalseString,
						signatureKind: item.SignatureKind.ToString(),
						status: FormatPackageStatus(packageStatus),
						capabilities: manifestDetails.Capabilities,
						capabilityCount: manifestDetails.CapabilityCount,
						vmRef: VVMRef
					));
				}
				catch (System.Runtime.InteropServices.COMException)
				{ /*
				     Do nothing.
				     It's thrown here: string? logoStr = item.Logo?.ToString();
				  */
				}
				catch (Exception ex)
				{
					try
					{
						Logger.Write(string.Format(Atlas.GetStr("AppDetailsErrorMessageWithName"), item.Id.FamilyName));
					}
					catch
					{
						Logger.Write(Atlas.GetStr("AppDetailsErrorMessageGeneric"));
					}
					Logger.Write(ex);
				}
			}

			return apps;
		});

	}

	internal static async Task PopulateStorageDetailsAsync(PackagedAppView app)
	{
		if (app.StorageDetailsLoaded)
		{
			return;
		}

		if (!app.TryBeginStorageDetailsLoad())
		{
			while (app.StorageDetailsLoading)
			{
				await Task.Delay(50);
			}

			return;
		}

		app.SetStorageDetailsLoading("…", "…", "…");

		try
		{
			PackagedAppStorageDetails storageDetails = await Task.Run(() =>
			{
				long? appSizeInBytes = GetDirectorySizeInBytes(app.InstallLocation);
				long? appDataSizeInBytes = GetAppDataSizeInBytes(app.PackageFamilyName);
				return new PackagedAppStorageDetails(appSizeInBytes, appDataSizeInBytes);
			});

			app.SetStorageDetails(
				FormatByteSize(storageDetails.AppSizeInBytes),
				FormatByteSize(storageDetails.AppDataSizeInBytes),
				FormatByteSize(storageDetails.TotalUsageInBytes));
		}
		catch
		{
			app.SetStorageDetails(
				Atlas.GetStr("UnavailableOrUnknown"),
				Atlas.GetStr("UnavailableOrUnknown"),
				Atlas.GetStr("UnavailableOrUnknown"));
		}
	}

	private static bool? GetPackageNonRemovable(Package package)
	{
		if (package.SignatureKind is PackageSignatureKind.System)
		{
			return true;
		}

		try
		{
			bool isPresent = false;
			int errorCode = NativeMethods.IsPackageFamilyInUninstallBlocklist(package.Id.FamilyName, ref isPresent);
			if (errorCode < 0)
			{
				Marshal.ThrowExceptionForHR(errorCode);
			}

			return isPresent;
		}
		catch
		{
			return null;
		}
	}

	private static string FormatPackageDependencies(Package package)
	{
		StringBuilder builder = new();
		bool hasValue = false;

		foreach (Package dependency in package.Dependencies)
		{
			hasValue = AppendDisplayListValue(builder, hasValue, dependency.Id.FullName);
		}

		return hasValue ? builder.ToString() : Atlas.GetStr("NAText");
	}

	private static string FormatDisplayList(IEnumerable<string> values)
	{
		StringBuilder builder = new();
		bool hasValue = false;

		foreach (string value in values)
		{
			hasValue = AppendDisplayListValue(builder, hasValue, value);
		}

		return hasValue ? builder.ToString() : Atlas.GetStr("NAText");
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool AppendDisplayListValue(StringBuilder builder, bool hasValue, string value)
	{
		ReadOnlySpan<char> trimmedValue = value.AsSpan().Trim();
		if (trimmedValue.IsEmpty)
		{
			return hasValue;
		}

		if (hasValue)
		{
			_ = builder.AppendLine();
		}

		_ = builder.Append(trimmedValue);
		return true;
	}

	private static readonly XmlReaderSettings ReaderSettings = new()
	{
		DtdProcessing = DtdProcessing.Prohibit,
		IgnoreComments = true,
		IgnoreWhitespace = true
	};

	private static string FormatPackageStatus(Windows.ApplicationModel.PackageStatus packageStatus)
	{
		if (packageStatus.VerifyIsOK())
		{
			return "Ok";
		}

		List<string> activeStates = [];

		if (packageStatus.DataOffline) activeStates.Add("DataOffline");
		if (packageStatus.DependencyIssue) activeStates.Add("DependencyIssue");
		if (packageStatus.DeploymentInProgress) activeStates.Add("DeploymentInProgress");
		if (packageStatus.Disabled) activeStates.Add("Disabled");
		if (packageStatus.IsPartiallyStaged) activeStates.Add("IsPartiallyStaged");
		if (packageStatus.LicenseIssue) activeStates.Add("LicenseIssue");
		if (packageStatus.Modified) activeStates.Add("Modified");
		if (packageStatus.NeedsRemediation) activeStates.Add("NeedsRemediation");
		if (packageStatus.NotAvailable) activeStates.Add("NotAvailable");
		if (packageStatus.PackageOffline) activeStates.Add("PackageOffline");
		if (packageStatus.Servicing) activeStates.Add("Servicing");
		if (packageStatus.Tampered) activeStates.Add("Tampered");

		return activeStates.Count > 0 ? string.Join(", ", activeStates) : Atlas.GetStr("NAText");
	}

	private static PackagedAppManifestDetails GetPackageManifestDetails(Package package)
	{
		try
		{
			string manifestPath = Path.Join(package.InstalledLocation.Path, "AppxManifest.xml");
			if (!File.Exists(manifestPath))
			{
				return new PackagedAppManifestDetails(Atlas.GetStr("NAText"), 0);
			}

			HashSet<string> capabilities = new(StringComparer.OrdinalIgnoreCase);
			bool readingCapabilities = false;

			using FileStream manifestStream = new(manifestPath, FileMode.Open, FileAccess.Read, FileShare.Read);
			using XmlReader reader = XmlReader.Create(manifestStream, ReaderSettings);

			while (reader.Read())
			{
				if (reader.NodeType == XmlNodeType.Element)
				{
					if (string.Equals(reader.LocalName, "Capabilities", StringComparison.Ordinal))
					{
						readingCapabilities = !reader.IsEmptyElement;
						continue;
					}

					if (readingCapabilities)
					{
						string capabilityValue = reader.GetAttribute("Name") ?? reader.LocalName;
						if (!string.IsNullOrWhiteSpace(capabilityValue))
						{
							_ = capabilities.Add(capabilityValue.Trim());
						}

						continue;
					}
				}
				else if (reader.NodeType == XmlNodeType.EndElement &&
					string.Equals(reader.LocalName, "Capabilities", StringComparison.Ordinal))
				{
					readingCapabilities = false;
				}
			}

			if (capabilities.Count == 0)
			{
				return new PackagedAppManifestDetails(Atlas.GetStr("NAText"), 0);
			}

			List<string> orderedCapabilities = [.. capabilities];
			orderedCapabilities.Sort(StringComparer.OrdinalIgnoreCase);

			return new PackagedAppManifestDetails(FormatDisplayList(orderedCapabilities), orderedCapabilities.Count);
		}
		catch
		{
			return new PackagedAppManifestDetails(Atlas.GetStr("NAText"), 0);
		}
	}

	private static string GetInstallLocation(Package package)
	{
		try
		{
			string effectivePath = package.EffectivePath;
			if (!string.IsNullOrWhiteSpace(effectivePath))
			{
				return effectivePath;
			}
		}
		catch { }

		return package.InstalledLocation.Path;
	}

	private static string GetPackageUserInformation(Package package)
	{
		if (!Atlas.IsElevated)
		{
			return "{}";
		}

		List<PackageUserInformation> packageUsers;

		try
		{
			packageUsers = [.. packageManager.FindUsers(package.Id.FullName)];
		}
		catch
		{
			return "{}";
		}

		if (packageUsers.Count is 0)
		{
			return "{}";
		}

		List<string> formattedUserInformation = new(packageUsers.Count);

		foreach (PackageUserInformation packageUser in CollectionsMarshal.AsSpan(packageUsers))
		{
			formattedUserInformation.Add(FormatPackageUserInformation(packageUser, package.Id.FullName));
		}

		return string.Concat("{", string.Join(", ", formattedUserInformation), "}");
	}

	private static string FormatPackageUserInformation(PackageUserInformation packageUser, string packageFullName)
	{
		string userSecurityId = packageUser.UserSecurityId;

		if (!SIDToNameDictionary.TryGetValue(userSecurityId, out string? userName))
		{
			try
			{
				SecurityIdentifier securityIdentifier = new(userSecurityId);
				string accountName = securityIdentifier.Translate(typeof(NTAccount)).Value;

				// NTAccount.Value returns "COMPUTERNAME\\Username" or "DOMAIN\\Username".
				// This keeps only the username portion.
				ReadOnlySpan<char> accountNameSpan = accountName.AsSpan();
				int separatorIndex = accountNameSpan.LastIndexOfAny('\\', '/');

				userName = separatorIndex >= 0 && separatorIndex < accountName.Length - 1
					? accountName[(separatorIndex + 1)..]
					: accountName;
			}
			catch
			{
				userName = userSecurityId;
			}

			SIDToNameDictionary[userSecurityId] = userName;
		}

		string installState = packageUser.InstallState.ToString();
		if (packageUser.InstallState == PackageInstallState.Installed)
		{
			bool isPackageEndOfLife = false;
			int errorCode = NativeMethods.IsPackageEndOfLife(userSecurityId, packageFullName, ref isPackageEndOfLife);
			if (errorCode < 0)
			{
				Marshal.ThrowExceptionForHR(errorCode);
				Logger.Write($"Received error code '{errorCode}' when querying end of life status of '{packageFullName}'");
			}

			if (isPackageEndOfLife)
			{
				installState = string.Concat(installState, "(pending removal)");
			}
		}

		return string.Concat(userName, ": ", installState);
	}

	/// <summary>
	/// Gets the total size of the package data folders that are exposed through ApplicationDataManager.
	/// </summary>
	private static long? GetAppDataSizeInBytes(string packageFamilyName)
	{
		try
		{
			using Windows.Storage.ApplicationData applicationData = ApplicationDataManager.CreateForPackageFamily(packageFamilyName);

			ReadOnlySpan<string?> appsRelatedDirectories = [
				applicationData.LocalFolder?.Path,
				applicationData.LocalCacheFolder?.Path,
				applicationData.RoamingFolder?.Path,
				applicationData.SharedLocalFolder?.Path,
				applicationData.TemporaryFolder?.Path
				];

			long totalSizeInBytes = 0;

			foreach (string? folderPath in appsRelatedDirectories)
			{
				long? currentFolderSize = GetDirectorySizeInBytes(folderPath);
				if (!currentFolderSize.HasValue)
				{
					continue;
				}

				totalSizeInBytes = SafeAdd(totalSizeInBytes, currentFolderSize.Value);
			}

			return totalSizeInBytes;
		}
		catch
		{
			return null;
		}
	}


	private static readonly EnumerationOptions EnumerationOptions = new()
	{
		AttributesToSkip = FileAttributes.ReparsePoint,
		IgnoreInaccessible = true,
		RecurseSubdirectories = true,
		ReturnSpecialDirectories = false
	};

	/// <summary>
	/// Recursively computes the size of a directory while ignoring inaccessible entries and reparse points.
	/// </summary>
	private static long? GetDirectorySizeInBytes(string? directoryPath)
	{
		if (!Directory.Exists(directoryPath))
		{
			return 0;
		}

		try
		{
			long totalSizeInBytes = 0;

			FileSystemEnumerable<long> fileSizes = new(
				directoryPath,
				static (ref entry) => entry.Length,
				EnumerationOptions)
			{
				ShouldIncludePredicate = static (ref entry) => !entry.IsDirectory,
				ShouldRecursePredicate = static (ref entry) => (entry.Attributes & FileAttributes.ReparsePoint) == 0
			};

			foreach (long fileSize in fileSizes)
			{
				totalSizeInBytes = SafeAdd(totalSizeInBytes, fileSize);
			}

			return totalSizeInBytes;
		}
		catch
		{
			return null;
		}
	}

	private static readonly string[] Suffixes = ["B", "KB", "MB", "GB", "TB"];

	/// <summary>
	/// Formats a byte count using the app's existing size formatting style.
	/// </summary>
	private static string FormatByteSize(long? sizeInBytes)
	{
		if (!sizeInBytes.HasValue)
		{
			return Atlas.GetStr("UnavailableOrUnknown");
		}

		int suffixIndex = 0;
		double size = sizeInBytes.Value;

		while (size >= 1024D && suffixIndex < Suffixes.Length - 1)
		{
			size /= 1024D;
			suffixIndex++;
		}

		return $"{size:F2} {Suffixes[suffixIndex]}";
	}

	/// <summary>
	/// Safely adds two byte counts and saturates at <see cref="long.MaxValue"/>.
	/// </summary>
	private static long SafeAdd(long left, long right)
	{
		if (right > 0 && left > long.MaxValue - right)
		{
			return long.MaxValue;
		}

		return left + right;
	}

	private static string FormatPackageVersion(PackageVersion version)
	{
		int majorLength = CountDigits(version.Major);
		int minorLength = CountDigits(version.Minor);
		int buildLength = CountDigits(version.Build);
		int revisionLength = CountDigits(version.Revision);
		int totalLength = majorLength + minorLength + buildLength + revisionLength + 3;

		return string.Create(totalLength, version, static (span, currentVersion) =>
		{
			int written = currentVersion.Major.TryFormat(span, out int charsWritten) ? charsWritten : 0;
			span[written++] = '.';
			_ = currentVersion.Minor.TryFormat(span[written..], out charsWritten);
			written += charsWritten;
			span[written++] = '.';
			_ = currentVersion.Build.TryFormat(span[written..], out charsWritten);
			written += charsWritten;
			span[written++] = '.';
			_ = currentVersion.Revision.TryFormat(span[written..], out _);
		});
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int CountDigits(ushort value)
	{
		if (value >= 10000)
		{
			return 5;
		}

		if (value >= 1000)
		{
			return 4;
		}

		if (value >= 100)
		{
			return 3;
		}

		return value >= 10 ? 2 : 1;
	}

	// To create a collection of grouped items, create a query that groups
	// an existing list, or returns a grouped collection from a database.
	// The following method is used to create the ItemsSource for our CollectionViewSource that is defined in XAML
	internal static async Task<(ObservableCollection<GroupInfoListForPackagedAppView>, List<GroupInfoListForPackagedAppView>)> GetAppsGroupedAsync(object? VMRef = null)
	{
		List<PackagedAppView> apps = await Get(VMRef);
		Dictionary<string, List<PackagedAppView>> groupedApps = new(StringComparer.Ordinal);

		foreach (PackagedAppView item in CollectionsMarshal.AsSpan(apps))
		{
			if (string.IsNullOrWhiteSpace(item.DisplayName))
			{
				continue;
			}

			string key = item.DisplayName[..1].ToUpperInvariant();
			ref List<PackagedAppView>? currentGroup = ref CollectionsMarshal.GetValueRefOrAddDefault(groupedApps, key, out _);
			currentGroup ??= [];
			currentGroup.Add(item);
		}

		List<string> orderedKeys = [.. groupedApps.Keys];
		orderedKeys.Sort(StringComparer.Ordinal);

		List<GroupInfoListForPackagedAppView> groupedResults = new(orderedKeys.Count);
		foreach (string key in CollectionsMarshal.AsSpan(orderedKeys))
		{
			groupedResults.Add(new GroupInfoListForPackagedAppView(items: groupedApps[key], key: key));
		}

		return (new(groupedResults), groupedResults);
	}

	/// <summary>
	/// Event handler for when the search box of apps list changes. Used by all ViewModels that perform searches among installed packaged apps.
	/// Used by AppControl Manager only.
	/// TODO: Consolidate this with GetFilteredAppsListItemsSource in the InstalledAppsManagementVM.
	/// </summary>
	internal static ObservableCollection<GroupInfoListForPackagedAppView> PFNAppFilteringTextBox_TextChanged(string? query, List<GroupInfoListForPackagedAppView> fullList)
	{
		if (string.IsNullOrWhiteSpace(query))
		{
			// If the filter is cleared, restore the original collection
			return new(fullList);
		}

		// Filter the original collection
		List<GroupInfoListForPackagedAppView> filtered = fullList
			.Select(group => new GroupInfoListForPackagedAppView(
				items: group.Where(app =>
				app.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
				app.FullName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
				app.Description.Contains(query, StringComparison.OrdinalIgnoreCase) ||
				app.PackageFamilyName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
				app.Publisher.Contains(query, StringComparison.OrdinalIgnoreCase) ||
				app.InstallLocation.Contains(query, StringComparison.OrdinalIgnoreCase) ||
				app.Dependencies.Contains(query, StringComparison.OrdinalIgnoreCase) ||
				app.Capabilities.Contains(query, StringComparison.OrdinalIgnoreCase) ||
				app.PublisherID.Contains(query, StringComparison.OrdinalIgnoreCase)
				), key: group.Key)).Where(group => group.Any()).ToList();

		return new ObservableCollection<GroupInfoListForPackagedAppView>(filtered);
	}

}

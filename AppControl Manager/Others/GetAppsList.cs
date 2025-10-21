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

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Windows.ApplicationModel;
using Windows.Management.Deployment;

namespace AppControlManager.Others;

internal static class GetAppsList
{

	// Package Manager object used by the PFN section
	private static readonly PackageManager packageManager = new();

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
			byte[] header = reader.ReadBytes(8);
			_ = stream.Seek(0, SeekOrigin.Begin);

			// PNG signature: 89 50 4E 47 0D 0A 1A 0A
			if (header.Length >= 8 && header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47)
			{
				return ReadPngDimensions(reader);
			}
			// JPEG signature: FF D8 FF
			else if (header.Length >= 3 && header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF)
			{
				return ReadJpegDimensions(reader);
			}
			// BMP signature: 42 4D
			else if (header.Length >= 2 && header[0] == 0x42 && header[1] == 0x4D)
			{
				return ReadBmpDimensions(reader);
			}
			// GIF signature: 47 49 46 38
			else if (header.Length >= 4 && header[0] == 0x47 && header[1] == 0x49 && header[2] == 0x46 && header[3] == 0x38)
			{
				return ReadGifDimensions(reader);
			}
			// ICO signature: 00 00 01 00
			else if (header.Length >= 4 && header[0] == 0x00 && header[1] == 0x00 && header[2] == 0x01 && header[3] == 0x00)
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
		byte[] bytes = reader.ReadBytes(4);
		return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
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

			// Get all of the packages on the system
			IEnumerable<Package> allApps = packageManager.FindPackages();

			// Loop over each package
			foreach (Package item in allApps)
			{
				try
				{
					// Try get the logo string
					string? logoStr = item.Logo?.ToString();

					// Validate that the logo string is a valid absolute URI and check size requirements
					// Many logos exist and are valid URI but are 1x1 pixels which makes them useless to show on the ListView.
					if (!Uri.TryCreate(logoStr, UriKind.Absolute, out _) ||
						!IsLogoSizeValid(logoStr))
					{
						// If invalid URI or size is less than 10x10, assign a fallback logo
						logoStr = GlobalVars.FallBackAppLogoURI;
					}

					// Create a new instance of the class that displays each app in the ListView
					apps.Add(new PackagedAppView(
						displayName: item.DisplayName,
						version: $"{item.Id.Version.Major}.{item.Id.Version.Minor}.{item.Id.Version.Build}.{item.Id.Version.Revision}",
						packageFamilyName: item.Id.FamilyName,
						logo: logoStr,
						publisher: item.PublisherDisplayName,
						architecture: item.Id.Architecture.ToString(),
						publisherID: item.Id.PublisherId,
						fullName: item.Id.FullName,
						description: string.IsNullOrEmpty(item.Description) ? "N/A" : item.Description,
						installLocation: item.InstalledLocation.Path,
						installedDate: item.InstalledDate.ToLocalTime().ToString(CultureInfo.CurrentCulture),
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
						Logger.Write(string.Format(GlobalVars.GetStr("AppDetailsErrorMessageWithName"), item.Id.FamilyName));
					}
					catch
					{
						Logger.Write(GlobalVars.GetStr("AppDetailsErrorMessageGeneric"));
					}
					Logger.Write(ex);
				}
			}

			return apps;
		});

	}


	// To create a collection of grouped items, create a query that groups
	// an existing list, or returns a grouped collection from a database.
	// The following method is used to create the ItemsSource for our CollectionViewSource that is defined in XAML
	internal static async Task<ObservableCollection<GroupInfoListForPackagedAppView>> GetContactsGroupedAsync(object? VMRef = null)
	{
		// Grab Apps objects from pre-existing list
		IEnumerable<GroupInfoListForPackagedAppView> query = from item in await Get(VMRef)

																 // Ensure DisplayName is not null before grouping
																 // This also prevents apps without a DisplayName to exist in the returned apps list
															 where !string.IsNullOrWhiteSpace(item.DisplayName)

															 // Group the items returned from the query, sort and select the ones you want to keep
															 group item by item.DisplayName[..1].ToUpperInvariant() into g
															 orderby g.Key

															 // GroupInfoListForPackagedAppView is a simple custom class that has an IEnumerable type attribute, and
															 // a key attribute. The IGrouping-typed variable g now holds the App objects,
															 // and these objects will be used to create a new GroupInfoListForPackagedAppView object.
															 select new GroupInfoListForPackagedAppView(items: g, key: g.Key);

		return new(query);
	}

}

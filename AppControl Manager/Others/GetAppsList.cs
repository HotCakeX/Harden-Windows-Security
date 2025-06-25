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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Windows.ApplicationModel;
using Windows.Management.Deployment;

namespace AppControlManager.Others;

internal static class GetAppsList
{

	// Package Manager object used by the PFN section
	private static readonly PackageManager packageManager = new();

	/// <summary>
	/// Gets the list of all installed Packaged Apps
	/// </summary>
	/// <returns></returns>
	private static async Task<List<PackagedAppView>> Get()
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

					// Validate that the logo string is a valid absolute URI
					if (!Uri.TryCreate(logoStr, UriKind.Absolute, out _))
					{
						// If invalid, assign a fallback logo
						logoStr = GlobalVars.FallBackAppLogoURI;
					}

					// Create a new instance of the class that displays each app in the ListView
					apps.Add(new PackagedAppView(
						displayName: item.DisplayName,
						version: string.Format(GlobalVars.GetStr("VersionLabelFormat"), item.Id.Version.Major, item.Id.Version.Minor, item.Id.Version.Build, item.Id.Version.Revision),
						packageFamilyName: string.Format(GlobalVars.GetStr("PFNLabelFormat"), item.Id.FamilyName),
						logo: logoStr,
						packageFamilyNameActual: item.Id.FamilyName
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
					Logger.Write(ErrorWriter.FormatException(ex));
				}
			}

			return apps;
		});

	}


	// To create a collection of grouped items, create a query that groups
	// an existing list, or returns a grouped collection from a database.
	// The following method is used to create the ItemsSource for our CollectionViewSource that is defined in XAML
	internal static async Task<ObservableCollection<GroupInfoListForPackagedAppView>> GetContactsGroupedAsync()
	{
		// Grab Apps objects from pre-existing list
		IEnumerable<GroupInfoListForPackagedAppView> query = from item in await Get()

																 // Ensure DisplayName is not null before grouping
																 // This also prevents apps without a DisplayName to exist in the returned apps list
															 where !string.IsNullOrWhiteSpace(item.DisplayName)

															 // Group the items returned from the query, sort and select the ones you want to keep
															 group item by item.DisplayName[..1].ToUpper() into g
															 orderby g.Key

															 // GroupInfoListForPackagedAppView is a simple custom class that has an IEnumerable type attribute, and
															 // a key attribute. The IGrouping-typed variable g now holds the App objects,
															 // and these objects will be used to create a new GroupInfoListForPackagedAppView object.
															 select new GroupInfoListForPackagedAppView(g) { Key = g.Key };

		return new(query);
	}

}

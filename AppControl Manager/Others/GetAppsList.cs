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
						version: $"Version: {item.Id.Version.Major}.{item.Id.Version.Minor}.{item.Id.Version.Build}.{item.Id.Version.Revision}",
						packageFamilyName: $"PFN: {item.Id.FamilyName}",
						logo: logoStr,
						packageFamilyNameActual: item.Id.FamilyName
						));
				}
				catch (Exception ex)
				{
					try
					{
						Logger.Write($"There was an error getting the details for the app: {item.Id.FamilyName}");
					}
					catch
					{
						Logger.Write("There was an error getting the details of an app");
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

		return [.. query];
	}

}

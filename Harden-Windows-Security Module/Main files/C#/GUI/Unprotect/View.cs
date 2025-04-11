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
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;

namespace HardenWindowsSecurity;

public partial class GUIMain
{
	public partial class NavigationVM : ViewModelBase
	{
		// Method to handle the Unprotect view, including loading
		private void UnprotectView(object? obj)
		{
			// Check if the view is already cached
			if (_viewCache.TryGetValue("UnprotectView", out var cachedView))
			{
				CurrentView = cachedView;
				return;
			}

			// if Admin privileges are not available, return and do not proceed any further
			// Will prevent the page from being loaded since the CurrentView won't be set/changed
			if (!Environment.IsPrivilegedProcess)
			{
				Logger.LogMessage("Unprotect page can only be used when running the Harden Windows Security Application with Administrator privileges", LogTypeIntel.ErrorInteractionRequired);
				return;
			}

			// Read the XAML content from the file
			string xamlContent = File.ReadAllText(Path.Combine(GlobalVars.path, "Resources", "XAML", "Unprotect.xaml"));

			// Parse the XAML content to create a UserControl
			UserControl View = (UserControl)XamlReader.Parse(xamlContent);

			// Finding the elements
			Grid ParentGrid = (Grid)View.FindName("ParentGrid");
			ComboBox AppControlPoliciesComboBox = (ComboBox)ParentGrid.FindName("AppControlPolicies");
			ComboBox UnprotectCategoriesComboBox = (ComboBox)ParentGrid.FindName("UnprotectCategories");
			Button RefreshDrivesButton = (Button)ParentGrid.FindName("RefreshDrivesForSelection");
			Button RemoveProtectionsButton = (Button)ParentGrid.FindName("RemoveProtectionsButton");
			Button DecryptButton = (Button)ParentGrid.FindName("DecryptButton");
			ComboBox ListOfDrivesComboBox = (ComboBox)ParentGrid.FindName("ListOfDrivesComboBox");

			// Register the elements that will be enabled/disabled based on current activity
			ActivityTracker.RegisterUIElement(RemoveProtectionsButton);
			ActivityTracker.RegisterUIElement(RefreshDrivesButton);
			ActivityTracker.RegisterUIElement(DecryptButton);

			byte? UnprotectCategoriesComboBoxSelection = null;
			byte? AppControlPoliciesComboBoxSelection = null;

			// Event handler for when the refresh button is pressed
			RefreshDrivesButton.Click += async (sender, e) =>
				{
					await Task.Run(() =>
					{
						// Get the drives list
						List<BitLocker.BitLockerVolume> allDrivesList = BitLocker.GetAllEncryptedVolumeInfo(false, false);

						// Update the ComboBox with the drives using Application's Dispatcher
						app.Dispatcher.Invoke(() =>
						{
							ListOfDrivesComboBox.ItemsSource = allDrivesList.Select(D => $"{D.MountPoint}");
						});
					});
				};


			// Event handler for the Decrypt Button
			DecryptButton.Click += async (sender, e) =>
			{

				// Only continue if there is no activity other places
				if (ActivityTracker.IsActive)
				{
					return;
				}

				try
				{

					// mark as activity started
					ActivityTracker.IsActive = true;

					// Reset this flag to false indicating no errors Occurred so far
					BitLocker.HasErrorsOccurred = false;

					// Variable to store the selected drive letter from the ComboBox
					string? SelectedDriveFromComboBox = null;

					// Using the Application dispatcher to query UI elements' values only
					app.Dispatcher.Invoke(() =>
					{
						SelectedDriveFromComboBox = ListOfDrivesComboBox.SelectedItem?.ToString();
					});


					// Perform the main tasks on another thread to avoid freezing the GUI
					await Task.Run(() =>
					{
						if (SelectedDriveFromComboBox is null)
						{
							Logger.LogMessage("No Drive selected", LogTypeIntel.ErrorInteractionRequired);
						}
						else
						{
							BitLocker.Disable(SelectedDriveFromComboBox);
						}
					});

				}
				finally
				{
					// mark as activity completed
					ActivityTracker.IsActive = false;
				}
			};


			// Initially set the App Control Policies ComboBox to disabled
			AppControlPoliciesComboBox.IsEnabled = false;

			// Event handler to disable the App Control ComboBox based on the value of the UnprotectCategories ComboBox
			UnprotectCategoriesComboBox.SelectionChanged += (s, e) =>
			{
				// Check if the selected index is 1 (Only Remove The AppControl Policies)
				if (UnprotectCategoriesComboBox.SelectedIndex == 1)
				{
					// Enable the AppControlPolicies ComboBox
					AppControlPoliciesComboBox.IsEnabled = true;
				}
				else
				{
					// Disable the AppControlPolicies ComboBox
					AppControlPoliciesComboBox.IsEnabled = false;
				}
			};


			// Set up the Click event handler for the RemoveProtectionsButton button
			RemoveProtectionsButton.Click += async (sender, e) =>
			{
				// Only continue if there is no activity other places
				if (ActivityTracker.IsActive)
				{
					return;
				}

				try
				{
					// mark as activity started
					ActivityTracker.IsActive = true;

					// This will be filled in the switch statement based on the selected category
					// And used to send to the Notification method to be used on the toast notification
					string NotificationMessage = string.Empty;

					// Disable the RemoveProtectionsButton button while processing
					Application.Current.Dispatcher.Invoke(() =>
					{
						// Store the values of the combo boxes in View variables since they need to be acquired through the Application dispatcher since they belong to the UI thread
						UnprotectCategoriesComboBoxSelection = (byte)UnprotectCategoriesComboBox.SelectedIndex;
						AppControlPoliciesComboBoxSelection = (byte)AppControlPoliciesComboBox.SelectedIndex;

					});

					// Run the Unprotect commands asynchronously in a different thread
					await Task.Run(() =>
					{
						// if LGPO doesn't already exist in the working directory, then download it
						if (!Path.Exists(GlobalVars.LGPOExe))
						{
							Logger.LogMessage("LGPO.exe doesn't exist, downloading it.", LogTypeIntel.Information);
							AsyncDownloader.PrepDownloadedFiles(GlobalVars.LGPOExe, null, null, true);
						}
						else
						{
							Logger.LogMessage("LGPO.exe already exists, skipping downloading it.", LogTypeIntel.Information);
						}


						switch (UnprotectCategoriesComboBoxSelection)
						{
							// Only Remove The Process Mitigations
							case 0:
								{
									NotificationMessage = "Process Mitigations";

									UnprotectWindowsSecurity.RemoveExploitMitigations();
									break;
								}
							// Only Remove The AppControl Policies
							case 1:
								{
									// Downloads Defense Measures
									if (AppControlPoliciesComboBoxSelection == 0)
									{
										NotificationMessage = "Downloads Defense Measures AppControl Policy";

										UnprotectWindowsSecurity.RemoveAppControlPolicies(true, false);
									}
									// Dangerous Script Hosts Blocking
									else if (AppControlPoliciesComboBoxSelection == 1)
									{
										NotificationMessage = "Dangerous Script Hosts Blocking AppControl Policy";

										UnprotectWindowsSecurity.RemoveAppControlPolicies(false, true);
									}
									// All AppControl Policies
									else
									{
										NotificationMessage = "AppControl Policies";

										UnprotectWindowsSecurity.RemoveAppControlPolicies(true, true);
									}

									break;
								}
							// Only Remove The Country IP Blocking Firewall Rules
							case 2:
								{
									NotificationMessage = "Country IP Blocking Firewall Rules";

									UnprotectWindowsSecurity.RemoveCountryIPBlockingFirewallRules();
									break;
								}
							// Remove All Protections
							case 3:
								{
									NotificationMessage = "Entire Applied Protections";

									UnprotectWindowsSecurity.RemoveAppControlPolicies(true, true);
									UnprotectWindowsSecurity.Unprotect();
									UnprotectWindowsSecurity.RemoveExploitMitigations();

									break;
								}

							default:
								break;
						}


						// Display notification at the end
						ToastNotification.Show(ToastNotification.Type.EndOfUnprotection, null, null, NotificationMessage, null);
					});
				}
				finally
				{
					// mark as activity completed
					ActivityTracker.IsActive = false;
				}
			};

			// Cache the view before setting it as the CurrentView
			_viewCache["UnprotectView"] = View;

			CurrentView = View;
		}
	}
}

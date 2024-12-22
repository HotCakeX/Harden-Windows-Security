using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class Deployment : Page, Sidebar.IAnimatedIconsManager
{
	// HashSets to store user input selected files
	private readonly HashSet<string> XMLFiles = [];
	private readonly HashSet<string> CIPFiles = [];

	public Deployment()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Enabled;
	}



	#region Augmentation Interface

	private string? unsignedBasePolicyPathFromSidebar;

	// Implement the SetVisibility method required by IAnimatedIconsManager
	public void SetVisibility(Visibility visibility, string? unsignedBasePolicyPath, Button button1, Button button2)
	{
		// Light up the local page's button icons
		UnsignedXMLFilesLightAnimatedIcon.Visibility = visibility;

		// Light up the sidebar buttons' icons
		button1.Visibility = visibility;

		// Set the incoming text which is from sidebar for unsigned policy path to a local private variable
		unsignedBasePolicyPathFromSidebar = unsignedBasePolicyPath;

		if (visibility is Visibility.Visible)
		{
			// Assign sidebar buttons' content texts
			button1.Content = "Deploy Unsigned Policy";

			// Assign a local event handler to the sidebar button
			button1.Click += LightUp1;
			// Save a reference to the event handler we just set for tracking
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect1EventHandler = LightUp1;

		}
	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void LightUp1(object sender, RoutedEventArgs e)
	{

		if (!string.IsNullOrWhiteSpace(unsignedBasePolicyPathFromSidebar))
		{
			if (XMLFiles.Add(unsignedBasePolicyPathFromSidebar))
			{
				// Append the new file to the TextBox, followed by a newline
				BrowseForXMLPolicyFilesButton_SelectedFilesTextBox.Text += unsignedBasePolicyPathFromSidebar + Environment.NewLine;
			}
		}

		BrowseForXMLPolicyFilesButton_Flyout.ShowAt(BrowseForXMLPolicyFilesButton);
	}

	#endregion




	/// <summary>
	/// Deploy unsigned XML files button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void DeployUnsignedXMLButton_Click(object sender, RoutedEventArgs e)
	{
		if (XMLFiles.Count is 0)
		{
			DeployUnsignedXMLButtonTeachingTip.IsOpen = true;
			return;
		}

		DeployUnsignedXMLButtonTeachingTip.IsOpen = false;

		bool errorsOccurred = false;

		try
		{
			// Disable all the deployment buttons during main operation
			DeployUnsignedXMLButton.IsEnabled = false;
			DeployCIPButton.IsEnabled = false;

			StatusInfoBar.Visibility = Visibility.Visible;
			StatusInfoBar.IsOpen = true;
			StatusInfoBar.Message = $"Deploying {XMLFiles.Count} unsigned XML files.";
			StatusInfoBar.Severity = InfoBarSeverity.Informational;
			StatusInfoBar.IsClosable = false;

			MainProgressRing.Visibility = Visibility.Visible;

			// Deploy the selected files
			await Task.Run(() =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("Deployments");

				// Convert and then deploy each XML file
				foreach (string file in XMLFiles)
				{

					// Instantiate the policy
					CodeIntegrityPolicy codeIntegrityPolicy = new(file, null);

					// Get all of the policy rule option nodes
					XmlNodeList? policyRuleOptionNodes = codeIntegrityPolicy.SiPolicyNode.SelectNodes("ns:Rules/ns:Rule", codeIntegrityPolicy.NamespaceManager);

					if (policyRuleOptionNodes is not null)
					{

						List<string> policyRuleOptions = [];

						foreach (XmlNode item in policyRuleOptionNodes)
						{
							policyRuleOptions.Add(item.InnerText);
						}

						bool isUnsigned = policyRuleOptions.Any(p => string.Equals(p, "Enabled:Unsigned System Integrity Policy", StringComparison.OrdinalIgnoreCase));

						if (!isUnsigned)
						{
							throw new InvalidOperationException($"The XML file '{file}' is a signed policy, use the signed policy deployment section instead!");
						}
					}


					string randomString = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUID();

					string xmlFileName = Path.GetFileName(file);

					string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						StatusInfoBar.Message = $"Currently Deploying XML file: '{file}'";
					});

					// Convert the XML file to CIP
					PolicyToCIPConverter.Convert(file, CIPFilePath);

					// Deploy the CIP file
					CiToolHelper.UpdatePolicy(CIPFilePath);

					// Delete the CIP file after deployment
					File.Delete(CIPFilePath);

				}
			});
		}

		catch
		{
			errorsOccurred = true;

			StatusInfoBar.Severity = InfoBarSeverity.Error;
			StatusInfoBar.Message = "There was an error deploying the selected XML files";

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				StatusInfoBar.Severity = InfoBarSeverity.Success;
				StatusInfoBar.Message = "Successfully deployed all of the selected XML files";

				// Clear the lists at the end if no errors occurred
				XMLFiles.Clear();

				BrowseForXMLPolicyFilesButton_SelectedFilesTextBox.Text = null;
			}

			// Re-enable all the deploy buttons
			DeployUnsignedXMLButton.IsEnabled = true;
			DeployCIPButton.IsEnabled = true;

			MainProgressRing.Visibility = Visibility.Collapsed;
			StatusInfoBar.IsClosable = true;
		}
	}








	/// <summary>
	/// Deploy CIP files button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void DeployCIPButton_Click(object sender, RoutedEventArgs e)
	{
		if (CIPFiles.Count is 0)
		{
			DeployCIPButtonTeachingTip.IsOpen = true;
			return;
		}

		DeployCIPButtonTeachingTip.IsOpen = false;

		bool errorsOccurred = false;

		try
		{
			DeployUnsignedXMLButton.IsEnabled = false;
			DeployCIPButton.IsEnabled = false;

			StatusInfoBar.Visibility = Visibility.Visible;
			StatusInfoBar.IsOpen = true;
			StatusInfoBar.Message = $"Deploying {CIPFiles.Count} CIP binary files.";
			StatusInfoBar.Severity = InfoBarSeverity.Informational;
			StatusInfoBar.IsClosable = false;

			MainProgressRing.Visibility = Visibility.Visible;

			// Deploy the selected CIP files
			await Task.Run(() =>
			{
				foreach (string file in CIPFiles)
				{
					_ = DispatcherQueue.TryEnqueue(() =>
					{
						StatusInfoBar.Message = $"Currently Deploying CIP file: '{file}'";
					});

					CiToolHelper.UpdatePolicy(file);
				}
			});
		}

		catch
		{
			errorsOccurred = true;

			StatusInfoBar.Severity = InfoBarSeverity.Error;
			StatusInfoBar.Message = "There was an error deploying the selected CIP files";

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				StatusInfoBar.Severity = InfoBarSeverity.Success;
				StatusInfoBar.Message = "Successfully deployed all of the selected CIP files";

				// Clear the list at the end if no errors occurred
				CIPFiles.Clear();

				BrowseForCIPBinaryFilesButton_SelectedFilesTextBox.Text = null;
			}

			DeployUnsignedXMLButton.IsEnabled = true;
			DeployCIPButton.IsEnabled = true;

			MainProgressRing.Visibility = Visibility.Collapsed;
			StatusInfoBar.IsClosable = true;
		}
	}





	/// <summary>
	/// Event handler for browse button - Unsigned XML files
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForXMLPolicyFilesButton_Click(object sender, RoutedEventArgs e)
	{
		string filter = "XML file|*.xml";

		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				if (XMLFiles.Add(file))
				{
					// Append the new file to the TextBox, followed by a newline
					BrowseForXMLPolicyFilesButton_SelectedFilesTextBox.Text += file + Environment.NewLine;
				}
			}
		}
	}


	/// <summary>
	/// Event handler for Browser button - CIP files
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForCIPBinaryFilesButton_Click(object sender, RoutedEventArgs e)
	{
		string filter = "CIP file|*.cip";

		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				if (CIPFiles.Add(file))
				{
					// Append the new file to the TextBox, followed by a newline
					BrowseForCIPBinaryFilesButton_SelectedFilesTextBox.Text += file + Environment.NewLine;
				}
			}
		}
	}


	/// <summary>
	/// Clear button for the CIP files deployment button flyout
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForCIPBinaryFilesButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		BrowseForCIPBinaryFilesButton_SelectedFilesTextBox.Text = null;
		CIPFiles.Clear();
	}


	/// <summary>
	/// Clear button for the unsigned files deployment button flyout
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForXMLPolicyFilesButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		BrowseForXMLPolicyFilesButton_SelectedFilesTextBox.Text = null;
		XMLFiles.Clear();
	}
}

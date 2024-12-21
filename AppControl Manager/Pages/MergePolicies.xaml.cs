using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class MergePolicies : Page
{

	private static string? mainPolicy;
	private static readonly HashSet<string> otherPolicies = [];
	private static bool shouldDeploy;

	public MergePolicies()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Enabled;
	}

	private async void MergeButton_Click(object sender, RoutedEventArgs e)
	{

		// Close the teaching tip if it's open when user presses the button
		// it will be opened again if necessary
		MergeButtonTeachingTip.IsOpen = false;

		if (string.IsNullOrWhiteSpace(mainPolicy))
		{
			MergeButtonTeachingTip.IsOpen = true;
			MergeButtonTeachingTip.Title = "Select main policy XML";
			MergeButtonTeachingTip.Subtitle = "You need to select an XML file as the main policy";
			return;
		}

		if (otherPolicies.Count == 0)
		{
			MergeButtonTeachingTip.IsOpen = true;
			MergeButtonTeachingTip.Title = "Select other policies";
			MergeButtonTeachingTip.Subtitle = "You need to select at least one more policy to merge with the main policy";
			return;
		}


		bool errorsOccurred = false;

		try
		{

			PolicyMergerInfoBar.IsOpen = true;

			PolicyMergerInfoBar.Message = "Merging the policies";

			MergeProgressRing.Visibility = Visibility.Visible;

			PolicyMergerInfoBar.Severity = InfoBarSeverity.Informational;

			await Task.Run(() =>
			{

				// Perform the merge operation
				SiPolicy.Merger.Merge(mainPolicy, otherPolicies);

				// If user chose to deploy the policy after merge
				if (shouldDeploy)
				{

					_ = DispatcherQueue.TryEnqueue(() =>
					 {
						 PolicyMergerInfoBar.Message = "Deploying the main policy after merge.";
					 });

					string stagingArea = (StagingArea.NewStagingArea("PolicyMerger")).FullName;

					string CIPPath = Path.Combine(stagingArea, "MergedPolicy.cip");

					PolicyToCIPConverter.Convert(mainPolicy, CIPPath);

					CiToolHelper.UpdatePolicy(CIPPath);
				}

			});

		}

		catch
		{
			errorsOccurred = true;

			throw;
		}

		finally
		{

			if (errorsOccurred)
			{
				PolicyMergerInfoBar.Severity = InfoBarSeverity.Error;
				PolicyMergerInfoBar.Message = "An error occurred during the merge process";
			}
			else
			{
				PolicyMergerInfoBar.Severity = InfoBarSeverity.Success;
				PolicyMergerInfoBar.Message = "Policies have been merged successfully";
			}

			PolicyMergerInfoBar.IsClosable = true;

			MergeProgressRing.Visibility = Visibility.Collapsed;
		}
	}

	private void DeployToggleButton_Click(object sender, RoutedEventArgs e)
	{
		shouldDeploy = ((ToggleButton)sender).IsChecked ?? false;
	}

	private void MainPolicyBrowseButton_Click(object sender, RoutedEventArgs e)
	{
		string filter = "XML file|*.xml";

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(filter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			mainPolicy = selectedFile;

			// Add the selected main XML policy file path to the flyout's TextBox
			MainPolicy_Flyout_TextBox.Text += selectedFile;
		}
	}

	private void MainPolicySettingsCard_Click(object sender, RoutedEventArgs e)
	{
		string filter = "XML file|*.xml";

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(filter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			mainPolicy = selectedFile;

			// Add the selected main XML policy file path to the flyout's TextBox
			MainPolicy_Flyout_TextBox.Text += selectedFile;
		}

		// Manually display the Flyout since user clicked/tapped on the Settings card and not the button itself
		MainPolicy_Flyout.ShowAt(MainPolicySettingsCard);
	}


	private void OtherPoliciesBrowseButton_Click(object sender, RoutedEventArgs e)
	{
		string filter = "XML file|*.xml";

		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				_ = otherPolicies.Add(file);

				// Append the new file to the TextBox, followed by a newline
				OtherPolicies_Flyout_TextBox.Text += file + Environment.NewLine;
			}
		}
	}



	private void OtherPoliciesSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		string filter = "XML file|*.xml";

		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				_ = otherPolicies.Add(file);

				// Append the new file to the TextBox, followed by a newline
				OtherPolicies_Flyout_TextBox.Text += file + Environment.NewLine;
			}
		}

		// Manually display the Flyout since user clicked/tapped on the Settings card and not the button itself
		OtherPolicies_Flyout.ShowAt(OtherPoliciesSettingsCard);
	}

	private void MainPolicy_Flyout_ClearButton(object sender, RoutedEventArgs e)
	{
		MainPolicy_Flyout_TextBox.Text = null;
		mainPolicy = null;
	}

	private void OtherPolicies_Flyout_ClearButton(object sender, RoutedEventArgs e)
	{
		OtherPolicies_Flyout_TextBox.Text = null;
		otherPolicies.Clear();
	}


}

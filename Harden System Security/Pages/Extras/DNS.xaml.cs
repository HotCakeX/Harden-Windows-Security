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
using HardenSystemSecurity.DNS;
using HardenSystemSecurity.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.Pages.Extras;

/// <summary>
/// The DNS page.
/// </summary>
internal sealed partial class DNS : Page, CommonCore.UI.IPageHeaderProvider
{
	private DNSVM ViewModel => ViewModelProvider.DNSVM;

	internal DNS() => InitializeComponent();

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => Atlas.GetStr("DNSNavigationViewItem/ToolTipService/ToolTip");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/DNS");

	/// <summary>
	/// Confirms deletion of the clicked row. Closing the drop-down first keeps the confirmation
	/// anchored to a control that remains visible even when the row is removed.
	/// </summary>
	private void DeleteDohCertificate_Click(object sender, RoutedEventArgs e)
	{
		if (!ViewModel.ElementsAreEnabled || sender is not Button { Tag: DohCertificateOption option })
		{
			return;
		}

		DohCertificateComboBox.IsDropDownOpen = false;
		TextBlock message = new()
		{
			Text = $"Delete {option.DisplayName}?\nThis removes the certificate from its personal store. For an app-generated certificate, its matching trusted-root copy is also removed. Other applications may use this certificate. The private key is not deleted.",
			TextWrapping = TextWrapping.Wrap,
			MaxWidth = 360
		};
		Button confirm = new() { Content = "Delete certificate" };
		StackPanel content = new() { Spacing = 12 };
		content.Children.Add(message);
		content.Children.Add(confirm);
		Flyout confirmation = new() { Content = content };
		confirm.Click += (_, args) =>
		{
			if (!ViewModel.ElementsAreEnabled)
			{
				message.Text = "Stop the running server before deleting a certificate.";
				return;
			}

			try
			{
				// Validate that the bound collection can be updated before changing any store.
				if (DohCertificateComboBox.ItemsSource is not IList<DohCertificateOption> options || options.IsReadOnly)
				{
					throw new InvalidOperationException("The certificate collection cannot be updated.");
				}
				DnsOverHttpsCertificateManager.DeleteCertificate(option);
				if (ViewModel.SelectedDohCertificate is DohCertificateOption selected &&
					selected.StoreLocation == option.StoreLocation &&
					string.Equals(selected.Thumbprint, option.Thumbprint, StringComparison.OrdinalIgnoreCase))
				{
					ViewModel.SelectedDohCertificate = null;
				}
				_ = options.Remove(option);
				// Rebind as well so a non-observable list refreshes immediately.
				DohCertificateOption? remainingSelection = ViewModel.SelectedDohCertificate;
				DohCertificateComboBox.ItemsSource = null;
				DohCertificateComboBox.ItemsSource = options;
				ViewModel.SelectedDohCertificate = remainingSelection;
				DohCertificateComboBox.SelectedItem = remainingSelection;
				confirmation.Hide();
			}
			catch (Exception exception)
			{
				// Keep the confirmation open so store-access failures are visible and can be retried.
				message.Text = $"Certificate deletion failed: {exception.Message}";
			}
		};
		confirmation.ShowAt(DohCertificateComboBox);
	}
}

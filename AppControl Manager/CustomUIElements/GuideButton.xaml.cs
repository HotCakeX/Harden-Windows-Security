using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

internal sealed partial class GuideButton : UserControl
{
	internal GuideButton()
	{
		InitializeComponent();
	}

	public Uri? NavigateUri
	{
		get => (Uri?)GetValue(NavigateUriProperty);
		set => SetValue(NavigateUriProperty, value);
	}

	public static readonly DependencyProperty NavigateUriProperty =
		DependencyProperty.Register(
			nameof(NavigateUri),
			typeof(Uri),
			typeof(HyperlinkButton),
			new PropertyMetadata(null)
		);
}

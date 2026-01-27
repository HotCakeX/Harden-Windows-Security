using System.Collections.ObjectModel;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

internal sealed partial class ColumnSelector : UserControl
{
	internal ColumnSelector() => InitializeComponent();

	/// <summary>
	/// Dependency Property to bind the ViewModel's ColumnSelectionItems to this control.
	/// </summary>
	public static readonly DependencyProperty ItemsSourceProperty =
		DependencyProperty.Register(
			nameof(ItemsSource),
			typeof(ObservableCollection<ColumnSelectionItem>),
			typeof(ColumnSelector),
			new PropertyMetadata(null));

	public ObservableCollection<ColumnSelectionItem> ItemsSource
	{
		get => (ObservableCollection<ColumnSelectionItem>)GetValue(ItemsSourceProperty);
		set => SetValue(ItemsSourceProperty, value);
	}

	private void SelectAll_Click(object sender, RoutedEventArgs e)
	{
		if (ItemsSource is null) return;

		foreach (var item in ItemsSource)
		{
			item.IsChecked = true;
		}
	}

	private void DeselectAll_Click(object sender, RoutedEventArgs e)
	{
		if (ItemsSource is null) return;

		foreach (var item in ItemsSource)
		{
			item.IsChecked = false;
		}
	}
}

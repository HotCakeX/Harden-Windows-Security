using System.Collections.ObjectModel;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

// https://learn.microsoft.com/en-us/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.contentdialog
internal sealed partial class CustomPatternBasedFilePath : ContentDialog
{

	internal static readonly ObservableCollection<FilePathPatternExample> FilePathPatternExamplesCollection = [

		new()
		{
			Example = "C:\\Windows\\*",
			Description = "Matches all files in the 'C:\\Windows' directory and its sub-directories."
		},
		new()
		{
			Example = "D:\\EnterpriseApps\\MyApp\\*",
			Description = "Matches all files in the 'D:\\EnterpriseApps\\MyApp\\' directory and its sub-directories."
		},
		new()
		{
			Example = "*\\Bing.exe",
			Description = "Matches any file(s) named 'Bing.exe' in any location."
		},
		new()
		{
			Example = "C:\\*\\CCMCACHE\\*\\7z????-x64.exe",
			Description = "Wildcards used in the middle of a path allow all files that match that pattern. In this example, both of these hypothetical paths would match: 'C:\\WINDOWS\\CCMCACHE\\12345\\7zabcd-x64.exe' and 'C:\\USERS\\AppControlUSER\\Downloads\\Malware\\CCMCACHE\\Pwned\\7zhaha-x64.exe'"
		},
		new()
		{
			Example = "C:\\Users\\UserName\\AppData\\Local\\Temp\\????????-????-????-????-????????????.tmp.node\"",
			Description = "This example allows any '.node' temporary file inside of the TEMP folder that has a GUID as file name."
		}
	];

	internal CustomPatternBasedFilePath()
	{
		this.InitializeComponent();

		XamlRoot = App.MainWindow?.Content.XamlRoot;

		CustomPatternBasedFilePathListView.ItemsSource = FilePathPatternExamplesCollection;
	}
}

internal sealed class FilePathPatternExample
{
	internal string? Example;
	internal string? Description;
}

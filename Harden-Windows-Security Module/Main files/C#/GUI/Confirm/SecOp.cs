using System;
using System.ComponentModel;
using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace HardenWindowsSecurity;


// Define the SecOp class, representing an individual security option in the data grid
public class SecOp : INotifyPropertyChanged
{
	// Private fields to hold property values

	// Stores whether the security option is compliant
	private bool _Compliant;

	// Stores the security option's character image
	private ImageSource? _characterImage;

	// Stores the background color for the security option
	private Brush? _bgColor;

	// Event to notify listeners when a property value changes
	public event PropertyChangedEventHandler? PropertyChanged;

	// Public property to get or set the security option's character image
	public ImageSource? CharacterImage
	{
		get => _characterImage;
		set
		{
			_characterImage = value;

			// Notify that the CharacterImage property has changed
			OnPropertyChanged(nameof(CharacterImage));
		}
	}

	// Public property to get or set the background color
	public Brush? BgColor
	{
		get => _bgColor;
		set
		{
			_bgColor = value;

			// Notify that the BgColor property has changed
			OnPropertyChanged(nameof(BgColor));
		}
	}

	// Public properties for security option details
	public string? FriendlyName { get; set; }
	public string? Value { get; set; }
	public string? Name { get; set; }
	public required ComplianceCategories Category { get; set; }
	public string? Method { get; set; }

	// Public property to get or set whether the security option is compliant
	public bool Compliant
	{
		get => _Compliant;
		set
		{
			_Compliant = value;

			// Update CharacterImage based on compliance
			CharacterImage = LoadImage(_Compliant ? "ConfirmationTrue.png" : "ConfirmationFalse.png");

			// Notify that the Compliant property has changed
			OnPropertyChanged(nameof(Compliant));
		}
	}

	// Method to notify listeners that a property value has changed
	protected void OnPropertyChanged(string propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}

	// Private method to load an image from the specified file name
	private static BitmapImage LoadImage(string fileName)
	{
		// Construct the full path to the image file
		string imagePath = Path.Combine(GlobalVars.path, "Resources", "Media", fileName);
		// Return the loaded image as a BitmapImage
		return new BitmapImage(new Uri(imagePath, UriKind.Absolute));
	}
}

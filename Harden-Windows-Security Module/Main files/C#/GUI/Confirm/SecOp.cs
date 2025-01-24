using System.ComponentModel;

namespace HardenWindowsSecurity;

// Define the SecOp class, representing an individual security option in the data grid
public class SecOp : INotifyPropertyChanged
{

	// Stores whether the security option is compliant
	private bool _Compliant;

	// Event to notify listeners when a property value changes
	public event PropertyChangedEventHandler? PropertyChanged;

	// Property to get the symbol based on compliance
	public string ComplianceSymbol
	{
		get
		{
			// Return the appropriate symbol based on the Compliant property
			return _Compliant ? "\uE73D" : "\uE73C";
		}
	}

	// Public property to get or set whether the security option is compliant
	public bool Compliant
	{
		get => _Compliant;
		set
		{
			_Compliant = value;
			// Notify that the Compliant property has changed
			OnPropertyChanged(nameof(Compliant));

			// Notify that the ComplianceSymbol property should be updated as well
			OnPropertyChanged(nameof(ComplianceSymbol));
		}
	}

	// Public properties for security option details
	public string? FriendlyName { get; set; }
	public string? Value { get; set; }
	public string? Name { get; set; }
	public required ComplianceCategories Category { get; set; }
	public string? Method { get; set; }

	// Method to notify listeners that a property value has changed
	protected void OnPropertyChanged(string propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}
}

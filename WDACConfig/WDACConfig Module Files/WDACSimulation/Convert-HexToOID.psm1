# Import the System.Formats.Asn1 namespaces
# This allows you to use the AsnReader and AsnWriter classes
using namespace System.Formats.Asn1

Function Convert-HexToOID {
    [CmdletBinding()]
    [OutputType([System.String])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()][System.String]$Hex
    )
    <#
.SYNOPSIS
  Converts a hexadecimal string to an OID
.DESCRIPTION
  Used for converting hexadecimal values found in the EKU sections of the WDAC policies to their respective OIDs.
.PARAMETER Hex
  The hexadecimal string to convert to an OID
.EXAMPLE
  Convert-HexToOID -Hex '010a2b0601040182374c0301'

  Returns '1.3.6.1.4.1.311.76.3.1'
.INPUTS
  System.String
.OUTPUTS
  System.String
  #>

    begin {
        # Convert the hexadecimal string to a byte array by looping through the string in pairs of two characters
        # and converting each pair to a byte using the base 16 (hexadecimal) system
        [System.Byte[]]$NumArray = for ($Index = 0; $Index -lt $Hex.Length; $Index += 2) {
            [System.Convert]::ToByte($Hex.Substring($Index, 2), 16)
        }
    }

    process {
        # Change the first byte from 1 to 6 because the hexadecimal string is missing the tag and length bytes
        # that are required for the ASN.1 encoding of an OID
        # The tag byte indicates the type of the data, and for an OID it is 6
        # The length byte indicates the number of bytes that follow the tag byte
        # and for this example it is 10 (0A in hexadecimal)
        $NumArray[0] = 6

        # Create an AsnReader object with the default encoding rules
        # This is a class that can read the ASN.1 BER, CER, and DER data formats
        # BER (Basic Encoding Rules) is the most flexible and widely used encoding rule
        # CER (Canonical Encoding Rules) is a subset of BER that ensures a unique encoding
        # DER (Distinguished Encoding Rules) is a subset of CER that ensures a deterministic encoding
        # The AsnReader object takes the byte array as input and the encoding rule as an argument
        [AsnReader]$AsnReader = New-Object -TypeName AsnReader -ArgumentList ($NumArray, [AsnEncodingRules]::BER)

        # Read the OID as an ObjectIdentifier
        # This is a method of the AsnReader class that returns the OID as a string
        # The first two numbers are derived from the first byte of the encoded data
        # The rest of the numbers are derived from the subsequent bytes using a base 128 (variable-length) system
        [System.String]$OID = $AsnReader.ReadObjectIdentifier()
    }

    End {
        # Return the OID value as string
        return $OID
    }
}
Export-ModuleMember -Function 'Convert-HexToOID'

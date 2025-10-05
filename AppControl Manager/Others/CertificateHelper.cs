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

using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AppControlManager.Others;

internal static class CertificateHelper
{

	// Provider and algorithm constants.
	private const uint PROV_RSA_FULL = 1;
	private const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
	private const uint CALG_MD2 = 0x8001;
	private const uint HP_HASHVAL = 0x2;


	/// <summary>
	/// Computes the MD2 hash of the given data using CryptoAPI.
	/// </summary>
	private static byte[] ComputeMd2(ReadOnlySpan<byte> data)
	{
		IntPtr hProv = IntPtr.Zero;
		IntPtr hHash = IntPtr.Zero;
		try
		{
			// Attempt to acquire a cryptographic provider context.
			// First, try with the default provider.
			if (!NativeMethods.CryptAcquireContextW(out hProv, null, null, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			{
				// If that fails, try specifying "Microsoft Base Cryptographic Provider v1.0"
				if (!NativeMethods.CryptAcquireContextW(out hProv, null, "Microsoft Base Cryptographic Provider v1.0", PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
				{
					int error = Marshal.GetLastPInvokeError();

					throw new InvalidOperationException(string.Format(
						GlobalVars.GetStr("CryptAcquireContextFailedMessage"),
						error));
				}
			}

			// Create an MD2 hash object.
			if (!NativeMethods.CryptCreateHash(hProv, CALG_MD2, IntPtr.Zero, 0, out hHash))
			{
				int error = Marshal.GetLastPInvokeError();

				throw new InvalidOperationException(string.Format(
					GlobalVars.GetStr("CryptCreateHashFailedMessage"),
					error));
			}

			// Feed the data into the hash object.
			byte[] dataArray = data.ToArray();
			if (!NativeMethods.CryptHashData(hHash, dataArray, (uint)dataArray.Length, 0))
			{
				int error = Marshal.GetLastPInvokeError();

				throw new InvalidOperationException(string.Format(
					GlobalVars.GetStr("CryptHashDataFailedMessage"),
					error));
			}

			// Determine the size of the hash value.
			uint hashSize = 0;
			if (!NativeMethods.CryptGetHashParam(hHash, HP_HASHVAL, null, ref hashSize, 0))
			{
				int error = Marshal.GetLastPInvokeError();

				throw new InvalidOperationException(string.Format(
					GlobalVars.GetStr("CryptGetHashParamSizeFailedMessage"),
					error));
			}

			// Allocate the buffer for the hash value.
			byte[] hashValue = new byte[hashSize];
			if (!NativeMethods.CryptGetHashParam(hHash, HP_HASHVAL, hashValue, ref hashSize, 0))
			{
				int error = Marshal.GetLastPInvokeError();

				throw new InvalidOperationException(string.Format(
					GlobalVars.GetStr("CryptGetHashParamValueFailedMessage"),
					error));
			}

			return hashValue;
		}
		finally
		{
			if (hHash != IntPtr.Zero)
			{
				_ = NativeMethods.CryptDestroyHash(hHash);
			}
			if (hProv != IntPtr.Zero)
			{
				_ = NativeMethods.CryptReleaseContext(hProv, 0);
			}
		}
	}


	/// <summary>
	/// Calculates the TBS value of a certificate
	/// </summary>
	/// <param name="cert"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static string GetTBSCertificate(X509Certificate2 cert)
	{
		// Get the raw data of the certificate.
		byte[] rawData = cert.RawData;

		// Create an ASN.1 reader to parse the certificate.
		AsnReader asnReader = new(rawData, AsnEncodingRules.DER);

		// Read the certificate sequence.
		AsnReader certificate = asnReader.ReadSequence();

		// Read the TBS (To be signed) value of the certificate
		ReadOnlyMemory<byte> tbsCertificate = certificate.ReadEncodedValue();

		// Read the signature algorithm sequence.
		AsnReader signatureAlgorithm = certificate.ReadSequence();

		// Read the algorithm OID of the signature.
		string algorithmOid = signatureAlgorithm.ReadObjectIdentifier();

		// Select the correct hash function. Here we add MD2 support.
		byte[] hash = algorithmOid switch
		{
			"1.2.840.113549.1.1.2" => ComputeMd2(tbsCertificate.Span), // MD2 with RSA encryption. Windows still allows drivers signed by MD2Rsa Root certificates to load.
			"1.2.840.113549.1.1.4" => MD5.HashData(tbsCertificate.Span),
			"1.2.840.113549.1.1.5" or "1.3.14.3.2.29" => SHA1.HashData(tbsCertificate.Span),  // sha-1WithRSAEncryption
			"1.2.840.113549.1.1.11" => SHA256.HashData(tbsCertificate.Span),
			"1.2.840.113549.1.1.12" => SHA384.HashData(tbsCertificate.Span),
			"1.2.840.113549.1.1.13" => SHA512.HashData(tbsCertificate.Span),
			// These are less likely to be used
			"1.2.840.10040.4.3" => SHA1.HashData(tbsCertificate.Span),
			"2.16.840.1.101.3.4.3.2" => SHA256.HashData(tbsCertificate.Span),
			"2.16.840.1.101.3.4.3.3" => SHA384.HashData(tbsCertificate.Span),
			"2.16.840.1.101.3.4.3.4" => SHA512.HashData(tbsCertificate.Span),
			"1.2.840.10045.4.1" => SHA1.HashData(tbsCertificate.Span),
			"1.2.840.10045.4.3.2" => SHA256.HashData(tbsCertificate.Span),
			"1.2.840.10045.4.3.3" => SHA384.HashData(tbsCertificate.Span),
			"1.2.840.10045.4.3.4" => SHA512.HashData(tbsCertificate.Span),
			"2.16.840.1.101.3.4.3.14" => SHA3_256.HashData(tbsCertificate.Span),
			"2.16.840.1.101.3.4.3.15" => SHA3_384.HashData(tbsCertificate.Span),
			"2.16.840.1.101.3.4.3.16" => SHA3_512.HashData(tbsCertificate.Span),
			_ => throw new InvalidOperationException(string.Format(
					GlobalVars.GetStr("NoHandlerForAlgorithmMessage"),
					algorithmOid)),
		};

		// Convert the hash to a hex string.
		string hexStringOutput = Convert.ToHexString(hash);
		return hexStringOutput;
	}

	/// <summary>
	/// Converts a hexadecimal string to an OID
	/// Used for converting hexadecimal values found in the EKU sections of the App Control policies to their respective OIDs.
	/// </summary>
	/// <param name="hex"></param>
	/// <returns></returns>
	/// <exception cref="ArgumentException"></exception>
	internal static string ConvertHexToOID(string hex)
	{
		if (string.IsNullOrEmpty(hex))
		{
			throw new ArgumentException(
				GlobalVars.GetStr("HexStringCannotBeNullOrEmptyMessage"),
				nameof(hex));
		}

		// Convert the hexadecimal string to a byte array by looping through the string in pairs of two characters
		// and converting each pair to a byte using the base 16 (hexadecimal) system
		byte[] numArray = new byte[hex.Length / 2];
		for (int i = 0; i < hex.Length; i += 2)
		{
			numArray[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
		}

		// Change the first byte from 1 to 6 because the hexadecimal string is missing the tag and length bytes
		// that are required for the ASN.1 encoding of an OID
		// The tag byte indicates the type of the data, and for an OID it is 6
		// The length byte indicates the number of bytes that follow the tag byte
		// and for this example it is 10 (0A in hexadecimal)
		numArray[0] = 6;

		// Create an AsnReader object with the default encoding rules
		// This is a class that can read the ASN.1 BER, CER, and DER data formats
		// BER (Basic Encoding Rules) is the most flexible and widely used encoding rule
		// CER (Canonical Encoding Rules) is a subset of BER that ensures a unique encoding
		// DER (Distinguished Encoding Rules) is a subset of CER that ensures a deterministic encoding
		// The AsnReader object takes the byte array as input and the encoding rule as an argument
		AsnReader asnReader = new(numArray, AsnEncodingRules.BER);

		// Read the OID as an ObjectIdentifier
		// This is a method of the AsnReader class that returns the OID as a string
		// The first two numbers are derived from the first byte of the encoded data
		// The rest of the numbers are derived from the subsequent bytes using a base 128 (variable-length) system
		string oid = asnReader.ReadObjectIdentifier();

		// Return the OID value as string
		return oid;
	}
}

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

using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace CommonCore;

internal static class Printer
{

	/// <summary>
	/// Wait briefly for the spooler to register the printer after the feature is enabled or the queue is added.
	/// </summary>
	internal static async Task<bool> WaitForPrinterInstallationAsync(string printerName)
	{
		for (int attempt = 0; attempt < 10; attempt++)
		{
			if (IsPrinterInstalled(printerName))
			{
				return true;
			}

			await Task.Delay(500);
		}

		return IsPrinterInstalled(printerName);
	}

	/// <summary>
	/// Creates the local Microsoft Print to PDF printer queue using the built-in driver and prompt port.
	/// </summary>
	internal static unsafe void AddMicrosoftPrintToPdfPrinterInternal()
	{
		if (IsPrinterInstalled(MicrosoftPrintToPdfPrinterName))
		{
			return;
		}

		nint printerInfoPtr = nint.Zero;
		nint printerHandle = nint.Zero;
		nint printerNamePtr = nint.Zero;
		nint portNamePtr = nint.Zero;
		nint driverNamePtr = nint.Zero;
		nint printProcessorPtr = nint.Zero;
		nint dataTypePtr = nint.Zero;

		try
		{
			printerNamePtr = Marshal.StringToHGlobalUni(MicrosoftPrintToPdfPrinterName);
			portNamePtr = Marshal.StringToHGlobalUni(MicrosoftPrintToPdfPortName);
			driverNamePtr = Marshal.StringToHGlobalUni(MicrosoftPrintToPdfDriverName);
			printProcessorPtr = Marshal.StringToHGlobalUni(MicrosoftPrintToPdfPrintProcessorName);
			dataTypePtr = Marshal.StringToHGlobalUni(MicrosoftPrintToPdfDataType);

			PRINTER_INFO_2W printerInfo = new()
			{
				pPrinterName = printerNamePtr,
				pPortName = portNamePtr,
				pDriverName = driverNamePtr,
				pPrintProcessor = printProcessorPtr,
				pDatatype = dataTypePtr,
				Attributes = PRINTER_ATTRIBUTE_LOCAL
			};

			printerInfoPtr = Marshal.AllocHGlobal(sizeof(PRINTER_INFO_2W));
			*(PRINTER_INFO_2W*)printerInfoPtr = printerInfo;

			printerHandle = NativeMethods.AddPrinterW(null, 2, printerInfoPtr);
			if (printerHandle == nint.Zero)
			{
				int lastError = Marshal.GetLastPInvokeError();
				throw new Win32Exception(lastError);
			}
		}
		finally
		{
			if (printerHandle != nint.Zero)
			{
				_ = NativeMethods.ClosePrinter(printerHandle);
			}

			if (printerInfoPtr != nint.Zero)
			{
				Marshal.FreeHGlobal(printerInfoPtr);
			}

			if (printerNamePtr != nint.Zero)
			{
				Marshal.FreeHGlobal(printerNamePtr);
			}

			if (portNamePtr != nint.Zero)
			{
				Marshal.FreeHGlobal(portNamePtr);
			}

			if (driverNamePtr != nint.Zero)
			{
				Marshal.FreeHGlobal(driverNamePtr);
			}

			if (printProcessorPtr != nint.Zero)
			{
				Marshal.FreeHGlobal(printProcessorPtr);
			}

			if (dataTypePtr != nint.Zero)
			{
				Marshal.FreeHGlobal(dataTypePtr);
			}
		}
	}

	/// <summary>
	/// Checks whether a printer queue with the specified name is currently registered on the system.
	/// </summary>
	internal static unsafe bool IsPrinterInstalled(string printerName)
	{
		_ = NativeMethods.EnumPrintersW(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, null, 4, nint.Zero, 0, out uint bytesNeeded, out _);

		int initialError = Marshal.GetLastPInvokeError();
		if (bytesNeeded == 0)
		{
			return false;
		}

		if (initialError is not ERROR_INSUFFICIENT_BUFFER and not ERROR_SUCCESS)
		{
			throw new Win32Exception(initialError);
		}

		nint buffer = Marshal.AllocHGlobal((int)bytesNeeded);
		try
		{
			bool enumerationResult = NativeMethods.EnumPrintersW(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, null, 4, buffer, bytesNeeded, out _, out uint printersReturned);
			if (!enumerationResult)
			{
				int lastError = Marshal.GetLastPInvokeError();
				throw new Win32Exception(lastError);
			}

			int printerCount = checked((int)printersReturned);
			PRINTER_INFO_4W* printers = (PRINTER_INFO_4W*)buffer;

			for (int index = 0; index < printerCount; index++)
			{
				PRINTER_INFO_4W currentPrinter = printers[index];
				string? currentPrinterName = Marshal.PtrToStringUni(currentPrinter.pPrinterName);

				if (currentPrinterName is not null && string.Equals(currentPrinterName, printerName, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}

			return false;
		}
		finally
		{
			Marshal.FreeHGlobal(buffer);
		}
	}

	internal const string MicrosoftPrintToPdfPrinterName = "Microsoft Print to PDF";
	internal const string MicrosoftPrintToPdfFeatureName = "Printing-PrintToPDFServices-Features";
	private const string MicrosoftPrintToPdfDriverName = "Microsoft Print To PDF";
	private const string MicrosoftPrintToPdfPortName = "PORTPROMPT:";
	private const string MicrosoftPrintToPdfPrintProcessorName = "WinPrint";
	private const string MicrosoftPrintToPdfDataType = "RAW";
	private const uint PRINTER_ENUM_LOCAL = 0x00000002;
	private const uint PRINTER_ENUM_CONNECTIONS = 0x00000004;
	private const uint PRINTER_ATTRIBUTE_LOCAL = 0x00000040;
	private const int ERROR_SUCCESS = 0;
	private const int ERROR_INSUFFICIENT_BUFFER = 122;

}

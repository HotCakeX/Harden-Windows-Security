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
using System.Diagnostics.Eventing.Reader;
using CommonCore.IncrementalCollection;

namespace AppControlManager.ViewModels;

internal sealed partial class SystemShutdownInfoDialogVM : ViewModelBase
{
	internal SystemShutdownInfoDialogVM()
	{
		// Initialize the column manager with specific definitions for this page
		ColumnManager = new ListViewColumnManager<ShutDownInfo>(
		[
			new("Time", "Time", x => x.Time.ToString(), useRawHeader: true),
			new("Type", "Type", x => x.Type, useRawHeader: true),
			new("Reason", "Reason", x => x.Reason, useRawHeader: true),
			new("User", "User", x => x.User, useRawHeader: true),
			new("Program", "Program", x => x.Program, useRawHeader: true)
		]);

		// To adjust the initial width of the columns, giving them nice paddings.
		ColumnManager.CalculateColumnWidths(ShutDownInfoSource);
	}

	internal async void GenerateData()
	{
		try
		{
			List<ShutDownInfo> events = GetLogs();

			ShutDownInfoSource.Clear();
			ShutDownInfoSource.AddRange(events);

			ColumnManager.CalculateColumnWidths(ShutDownInfoSource);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	private static List<ShutDownInfo> GetLogs()
	{
		const string query = "*[System[(EventID=1074)]]";
		const string CodeIntegrityLogPath = "System";

		string pcName = $" ({Environment.MachineName})";

		List<ShutDownInfo> output = [];

		// Initialize the EventLogQuery with the log path and query
		EventLogQuery eventQuery = new(CodeIntegrityLogPath, PathType.LogName, query);

		// Read the events from the system based on the query
		using (EventLogReader logReader = new(eventQuery))
		{
			EventRecord eventRecord;

			// Read each event that matches the query
			while ((eventRecord = logReader.ReadEvent()) is not null)
			{
				try
				{
					// Get the XML string directly
					ReadOnlySpan<char> xmlSpan = eventRecord.ToXml().AsSpan();

					// Program has computer name at the end, which we try to remove here.
					ReadOnlySpan<char> program = CommonCore.IntelGathering.GetEventLogsData.GetStringValue(xmlSpan, "param1");
					int pcNameIndex = program.IndexOf(pcName, StringComparison.OrdinalIgnoreCase);
					if (pcNameIndex > 0)
					{
						program = program[..pcNameIndex];
					}

					output.Add(new(
						time: eventRecord.TimeCreated,
						type: CommonCore.IntelGathering.GetEventLogsData.GetStringValue(xmlSpan, "param5"),
						reason: CommonCore.IntelGathering.GetEventLogsData.GetStringValue(xmlSpan, "param3"),
						user: CommonCore.IntelGathering.GetEventLogsData.GetStringValue(xmlSpan, "param7"),
						program: program.ToString()
						));
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
				}
				finally
				{
					eventRecord.Dispose();
				}
			}
		}

		// Sort to show the newest event at top first
		output.Sort((x, y) => Nullable.Compare(y.Time, x.Time));

		return output;
	}

	// The Column Manager Composition
	internal readonly ListViewColumnManager<ShutDownInfo> ColumnManager;

	// ListView source.
	internal readonly RangedObservableCollection<ShutDownInfo> ShutDownInfoSource = [];
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace HardeningModule
{
    public class CimInstanceCSVRecord
    {
        public string Category { get; set; }
        public string CimInstance { get; set; }
        public string FriendlyName { get; set; }
        public object CompliantValue { get; set; }
    }

    public class CimInstanceCSVParser
    {
        public static List<CimInstanceCSVRecord> ReadCsv(string path)
        {
            List<CimInstanceCSVRecord> records = new List<CimInstanceCSVRecord>();

            using (StreamReader reader = new StreamReader(path))
            {
                string header = reader.ReadLine();
                if (header == null) return records;

                while (!reader.EndOfStream)
                {
                    string line = reader.ReadLine();
                    if (line == null) continue;

                    string[] fields = ParseCsvLine(line);
                    if (fields.Length == 4)
                    {
                        records.Add(new CimInstanceCSVRecord
                        {
                            Category = fields[0],
                            CimInstance = fields[1],
                            FriendlyName = fields[2],
                            CompliantValue = ParseCompliantValue(fields[3])
                        });
                    }
                    else
                    {
                        throw new ArgumentException("The CSV file is not formatted correctly. There should be 4 fields in each line.");
                    }
                }
            }

            return records;
        }

        private static string[] ParseCsvLine(string line)
        {
            List<string> fields = new List<string>();
            StringBuilder currentField = new StringBuilder();
            bool inQuotes = false;

            foreach (char c in line)
            {
                if (c == '"')
                {
                    inQuotes = !inQuotes;
                }
                else if (c == ',' && !inQuotes)
                {
                    fields.Add(currentField.ToString().Trim('"'));
                    currentField.Clear();
                }
                else
                {
                    currentField.Append(c);
                }
            }

            fields.Add(currentField.ToString().Trim('"'));
            return fields.ToArray();
        }

        private static object ParseCompliantValue(string value)
        {
            if (value.Contains(","))
            {
                return value.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            }
            return value;
        }
    }
}

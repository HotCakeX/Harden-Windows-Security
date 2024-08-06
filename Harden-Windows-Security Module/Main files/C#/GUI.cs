using System;
using System.Collections;
using System.Collections.Concurrent;

namespace HardeningModule
{
    /// <summary>
    /// A class to store all of the data that is related to the GUI and its operations
    /// </summary>
    public static class GUI
    {
        // A synchronized hashtable to store all of the data that needs to be shared between the RunSpaces and ThreadJobs
        public static Hashtable SyncHash = Hashtable.Synchronized(new Hashtable());

        public static string MicrosoftSecurityBaselineZipPath = string.Empty;

        public static string Microsoft365AppsSecurityBaselineZipPath = string.Empty;

        public static string LGPOZipPath = string.Empty;

        // List of all the selected categories in a thread safe way
        public static ConcurrentQueue<string> SelectedCategories = new ConcurrentQueue<string>();

        // List of all the selected subcategories in a thread safe way
        public static ConcurrentQueue<string> SelectedSubCategories = new ConcurrentQueue<string>();

        // To store the log messages in a thread safe way that will be displayed on the GUI and stored in the Logs text file
        public static ArrayList Logger = ArrayList.Synchronized(new ArrayList());
    }
}

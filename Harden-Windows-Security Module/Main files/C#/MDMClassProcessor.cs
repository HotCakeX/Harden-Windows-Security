using System;
using System.Collections.Generic;

namespace HardeningModule
{
    public partial class MDMClassProcessor
    {
        public static List<HardeningModule.MDMClassProcessor> Process()
        {
            List<HardeningModule.MDMClassProcessor> OutputList = new List<HardeningModule.MDMClassProcessor>();

            Dictionary<string, List<object>> CimInstancesOutput = HardeningModule.MDM.Get();




            return OutputList;
        }

    }
}
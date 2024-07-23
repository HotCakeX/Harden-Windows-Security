using System;
using System.Collections.Generic;

namespace HardeningModule
{
    public partial class MDMClassProcessor
    {
        public static List<HardeningModule.MDMClassProcessor> Process()
        {
            List<HardeningModule.MDMClassProcessor> OutputList = new List<HardeningModule.MDMClassProcessor>();

            var CimInstancesOutput = HardeningModule.MDM.Get();

            foreach (var Item in CimInstancesOutput.GetEnumerator()){

            }


            return OutputList;
        }

    }
}
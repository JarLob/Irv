using System;
using System.Collections.Generic;
using System.Linq;

namespace Irv.Engine
{
    internal class InsertionsMap : List<InsertionArea>
    {
        private InsertionsMap(){}

        public static InsertionsMap FindAllPrecise(IEnumerable<RequestValidationParam> taintfulParams, string text)
        {
            var result = new InsertionsMap();

            foreach (var taintfullParam in taintfulParams)
            {
                var currentIndex = 0;

                while (currentIndex < text.Length)
                {
                    var j = text.IndexOf(taintfullParam.Value, currentIndex, StringComparison.Ordinal);
                    if (j >= 0)
                    {
                        result.Add(new InsertionArea(j, taintfullParam));
                        currentIndex = j + taintfullParam.Value.Length;
                    }
                    else
                    {
                        currentIndex++;
                    }
                }
            }
            return result;
        }

        public static InsertionsMap FindAllFuzzy(IEnumerable<RequestValidationParam> taintfulParams, string text,
                                                 double treshold)
        {
            //TODO: Implement fuzzy insertions search
            throw new NotImplementedException();
        }

        public IEnumerable<InsertionArea> FindAllHaving(int position)
        {
            return this.Where(insertionArea => insertionArea.Includes(position));
        }
    }
}

namespace Irv.Engine
{
    internal class InsertionArea
    {
        public readonly int BeginPosition;
        public readonly int EndPosition;
        public readonly RequestValidationParam Param;

        public InsertionArea(int beginPosition, RequestValidationParam param)
        {
            BeginPosition = beginPosition;
            EndPosition = beginPosition + param.Value.Length;
            Param = param;
        }

        public bool Includes(int position)
        {
            return position >= BeginPosition && position <= EndPosition;
        }

        public bool Includes(int beginPosition, int endPosition)
        {
            return (beginPosition >= BeginPosition) && (beginPosition <= EndPosition) ||
                   (BeginPosition >= beginPosition) && (BeginPosition <= endPosition);
        }
    }
}

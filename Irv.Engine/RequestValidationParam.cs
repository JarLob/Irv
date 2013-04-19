namespace Irv.Engine
{
    internal class RequestValidationParam
    {
        public readonly string Source;
        public readonly string CollectionKey;
        public readonly string Value;

        public RequestValidationParam(string source, string collectionKey, string value)
        {
            Source = source;
            CollectionKey = collectionKey;
            Value = value;
        }
    }
}

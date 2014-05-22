using System;
using System.IO;
using System.Linq.Expressions;
using System.Text;
using System.Web.Caching;

namespace Irv.Engine
{
    internal class ResponseFilter : Stream
    {
        private readonly Stream _base;

        private readonly Encoding _encoding;

        public string Response { get; set; }

            
        public ResponseFilter(Stream stream, Encoding encoding)
        {
            _base = stream;
            _encoding = encoding;
        }

        public override void Flush()
        {
            var buffer = _encoding.GetBytes(Response);
            _base.Write(buffer, 0, buffer.Length);
            _base.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _base.Read(buffer, offset, count);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Response += _encoding.GetString(buffer);
        }

        public override string ToString()
        {
            return Response;
        }

        public override bool CanRead
        {
            get { return true; }
        }

        public override bool CanSeek
        {
            get { return true; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return _base.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            _base.SetLength(value);
        }

        public override long Length
        {
            get { return _base.Length; }
        }

        public override long Position
        {
            get
            {
                return _base.Position;
            }
            set { _base.Position = value; }
        }
    }
}

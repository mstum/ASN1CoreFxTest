using System;
using System.Numerics;

namespace ASN1Serialize
{
    /// <summary>
    /// Microseconds    ::= INTEGER (0..999999)
    ///                     -- microseconds
    /// </summary>
    internal class MicrosecondsAttribute : LimitedRangeIntegerAttribute
    {
        internal override Type[] ExpectedTypes => new Type[] { typeof(Microseconds) };

        public MicrosecondsAttribute()
            : base(0, 999999)
        {
        }

        protected override object ConvertDeserializedValue(BigInteger value)
            => new Microseconds((int)value);
    }
}

using System.Numerics;
using System.Security.Cryptography.Asn1;

namespace ASN1Serialize
{
    internal class LimitedRangeIntegerAttribute : IntegerAttribute
    {
        public BigInteger MinInclusive { get; }
        public BigInteger MaxInclusive { get; }

        public LimitedRangeIntegerAttribute(BigInteger minInclusive, BigInteger maxInclusive)
        {
            MinInclusive = minInclusive;
            MaxInclusive = maxInclusive;
        }
        internal override Asn1Deserializer.Deserializer Deserialize => Deserializer;

        protected object Deserializer(AsnReader reader)
        {
            var bigint = reader.GetInteger();
            if (bigint < MinInclusive || bigint > MaxInclusive)
            {
                throw new AsnSerializationConstraintException($"Value must range from {MinInclusive} to {MaxInclusive}, but was " + bigint);
            }
            return ConvertDeserializedValue(bigint);
        }

        protected virtual object ConvertDeserializedValue(BigInteger value)
        {
            return value;
        }
    }
}

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
namespace System.Security.Cryptography.Asn1
{
    internal abstract class AsnEncodingRuleAttribute : Attribute
    {
        internal AsnEncodingRuleAttribute()
        {
        }
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class OptionalValueAttribute : AsnEncodingRuleAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class DefaultValueAttribute : AsnEncodingRuleAttribute
    {
        internal byte[] EncodedBytes { get; }

        public DefaultValueAttribute(params byte[] encodedValue)
        {
            EncodedBytes = encodedValue;
        }

        public ReadOnlyMemory<byte> EncodedValue => EncodedBytes;
    }
}

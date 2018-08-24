// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
using System.Collections.Generic;

namespace System.Security.Cryptography.Asn1
{
    internal abstract class AsnTypeAttribute : Attribute
    {
        internal virtual Type[] ExpectedTypes { get; } = null;
        internal virtual ASN1Serialize.Asn1Deserializer.Deserializer Deserialize { get; } = null;

        internal AsnTypeAttribute()
        {
        }

        // TODO: Overridable Methods to do custom De-/Serialization, Verification, etc.
        // (e.g., Microseconds in an Integer between 0 and 999999. Or KdcFlags needs to be at least 32 Bits.
        // Deserialize(Reader) => Do the entire deserialization
        // AfterDeserialization(deserializedValue) => Use the default deserializer of the parent attribute,
        //                                            but massage the value afterwards
        // Validate(deserializedValue)
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class OctetStringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class BitStringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class AnyValueAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class ObjectIdentifierAttribute : AsnTypeAttribute
    {
        public bool PopulateFriendlyName { get; set; }
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class BMPStringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class IA5StringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class UTF8StringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class PrintableStringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class VisibleStringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class GeneralStringAttribute : AsnTypeAttribute
    {
        public UniversalTagNumber EncodingType { get; }

        public GeneralStringAttribute(UniversalTagNumber encodingType)
        {
            EncodingType = encodingType;
        }
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class SequenceOfAttribute : AsnTypeAttribute
    {
        internal Type FieldTypeAsnAttribute; // Make this an attribute? Any way to avoid Activator.CreateInstance?
        // Possibly best to add some sort of "Priority" or similar property to AsnType, so I can do:
        //
        // [GeneralString(UniversalTagNumber.IA5String)]
        // [SequenceOf]
        // [ExpectedTag(1)]
        // public string[] Name;
        //
        // But really, it's an array - why need the [SequenceOf] at all?
        // In theory, any IEnumerable that's not a string could be implicitly a Sequence.

        public SequenceOfAttribute()
        {
        }

        public SequenceOfAttribute(Type fieldType)
        {
            FieldTypeAsnAttribute = fieldType;
        }
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class SetOfAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class IntegerAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class UtcTimeAttribute : AsnTypeAttribute
    {
        public int TwoDigitYearMax { get; set; }
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Struct | AttributeTargets.Class)]
    internal class GeneralizedTimeAttribute : AsnTypeAttribute
    {
        public bool DisallowFractions { get; set; }
    }
}

﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
namespace System.Security.Cryptography.Asn1
{
    internal abstract class AsnTypeAttribute : Attribute
    {
        internal AsnTypeAttribute()
        {
        }
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class OctetStringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class BitStringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class AnyValueAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class ObjectIdentifierAttribute : AsnTypeAttribute
    {
        public bool PopulateFriendlyName { get; set; }
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class BMPStringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class IA5StringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class UTF8StringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class PrintableStringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class VisibleStringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class SequenceOfAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class SetOfAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class IntegerAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class UtcTimeAttribute : AsnTypeAttribute
    {
        public int TwoDigitYearMax { get; set; }
    }

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Struct | AttributeTargets.Class)]
    internal sealed class GeneralizedTimeAttribute : AsnTypeAttribute
    {
        public bool DisallowFractions { get; set; }
    }
}

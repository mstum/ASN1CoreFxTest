// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
namespace System.Security.Cryptography.Asn1
{
    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class ExpectedTagAttribute : Attribute
    {
        public TagClass TagClass { get; }
        public int TagValue { get; }
        public bool ExplicitTag { get; set; }

        public ExpectedTagAttribute(int tagValue)
            : this(TagClass.ContextSpecific, tagValue)
        {
        }

        public ExpectedTagAttribute(TagClass tagClass, int tagValue)
        {
            TagClass = tagClass;
            TagValue = tagValue;
        }
    }
}

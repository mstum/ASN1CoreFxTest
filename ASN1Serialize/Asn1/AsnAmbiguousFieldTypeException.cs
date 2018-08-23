// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
using System.Reflection;

namespace System.Security.Cryptography.Asn1
{
    internal class AsnAmbiguousFieldTypeException : AsnSerializationConstraintException
    {
        public AsnAmbiguousFieldTypeException(FieldInfo fieldInfo, Type ambiguousType)
            : base(SR.Format(SR.Cryptography_AsnSerializer_AmbiguousFieldType, fieldInfo.Name, fieldInfo.DeclaringType.FullName, ambiguousType.Namespace))
        {
        }
    }
}

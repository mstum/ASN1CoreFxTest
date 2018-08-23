// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
namespace System.Security.Cryptography.Asn1
{
    internal class AsnSerializerInvalidDefaultException : AsnSerializationConstraintException
    {
        internal AsnSerializerInvalidDefaultException()
        {
        }

        internal AsnSerializerInvalidDefaultException(Exception innerException)
            : base(string.Empty, innerException)
        {
        }
    }
}

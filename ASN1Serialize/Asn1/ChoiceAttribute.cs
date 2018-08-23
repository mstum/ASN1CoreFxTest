// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
namespace System.Security.Cryptography.Asn1
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct)]
    internal sealed class ChoiceAttribute : Attribute
    {
        public bool AllowNull { get; set; }
    }
}

﻿using System.Security.Cryptography.Asn1;

namespace ASN1Serialize
{
    /// <summary>
    /// PrincipalName   ::= SEQUENCE {
    ///         name-type       [0] Int32,
    ///         name-string     [1] SEQUENCE OF KerberosString
    /// }
    /// </summary>
    [SequenceOf]
    internal struct PrincipalName
    {
        [Integer]
        [ExpectedTag(0)]
        public NameType Type;

        //[KerberosString]
        [SequenceOf(typeof(KerberosStringAttribute))]
        [ExpectedTag(1)]
        public string[] Name;
    }
}

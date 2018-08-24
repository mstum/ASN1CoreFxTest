using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace ASN1Serialize
{
    /// <summary>
    /// KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
    ///         pvno            [0] INTEGER (5),
    ///         msg-type        [1] INTEGER (30),
    ///         ctime           [2] KerberosTime OPTIONAL,
    ///         cusec           [3] Microseconds OPTIONAL,
    ///         stime           [4] KerberosTime,
    ///         susec           [5] Microseconds,
    ///         error-code      [6] Int32,
    ///         crealm          [7] Realm OPTIONAL,
    ///         cname           [8] PrincipalName OPTIONAL,
    ///         realm           [9] Realm -- service realm --,
    ///         sname           [10] PrincipalName -- service name --,
    ///         e-text          [11] KerberosString OPTIONAL,
    ///         e-data          [12] OCTET STRING OPTIONAL
    /// }
    /// </summary>
    [SequenceOf]
    [ExpectedTag(TagClass.Application, 30)]
    [StructLayout(LayoutKind.Sequential)]
    internal struct KerberosError
    {
        [Integer]
        [ExpectedTag(0)]
        public int ProtocolVersionNumber;

        [Integer]
        [ExpectedTag(1)]
        public MessageType MessageType;

        [OptionalValue]
        [GeneralizedTime]
        [ExpectedTag(2)]
        public DateTimeOffset? CTime;

        [OptionalValue]
        [Integer]
        [ExpectedTag(3)]
        //public Microseconds? CUsec;
        public int? CUsec;

        [GeneralizedTime]
        [ExpectedTag(4)]
        public DateTimeOffset STime;

        [Integer]
        [ExpectedTag(5)]
        //public Microseconds? SUsec;
        public int? SUsec;

        [Integer]
        [ExpectedTag(6)]
        public KrbErrorCode ErrorCode;

        [OptionalValue]
        [Realm]
        [ExpectedTag(7)]
        public string CRealm;

        [OptionalValue]
        [ExpectedTag(8)]
        public PrincipalName? CName;

        [Realm]
        [ExpectedTag(9)]
        public string ServiceRealm;

        [ExpectedTag(10)]
        public PrincipalName SName;

        [OptionalValue]
        [KerberosString]
        [ExpectedTag(11)]
        public string EText;

        [OptionalValue]
        [OctetString]
        [ExpectedTag(12)]
        public ReadOnlyMemory<byte>? EData;
    }
}
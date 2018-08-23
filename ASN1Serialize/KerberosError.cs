using System;
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
    internal struct KerberosError
    {
        [Integer]
        [ExpectedTag(0)]
        public int ProtocolVersionNumber { get; set; }

        [Integer]
        [ExpectedTag(1)]
        public MessageType MessageType { get; set; }

        [GeneralizedTime]
        [ExpectedTag(2)]
        public DateTimeOffset CTime { get; set; }

        [Integer]
        [ExpectedTag(3)]
        public Microseconds? CUsec { get; set; }

        [GeneralizedTime]
        [ExpectedTag(4)]
        public DateTimeOffset STime { get; set; }

        [Integer]
        [ExpectedTag(5)]
        public Microseconds? SUsec { get; set; }

        [Integer]
        [ExpectedTag(6)]
        public KrbErrorCode ErrorCode { get; set; }

        [Realm]
        [ExpectedTag(7)]
        public string CRealm { get; set; }

        [ExpectedTag(8)]
        public PrincipalName CName { get; set; }

        [Realm]
        [ExpectedTag(9)]
        public string ServiceRealm { get; set; }

        [ExpectedTag(10)]
        public PrincipalName SName { get; set; }

        [KerberosString]
        [ExpectedTag(11)]
        public string EText { get; set; }

        [OctetString]
        [ExpectedTag(12)]
        public byte[] EData { get; set; }
    }
}
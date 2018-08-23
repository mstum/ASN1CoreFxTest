using System;

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
    internal class KerberosError
    {
        public int ProtocolVersionNumber { get; set; }
        public MessageType MessageType { get; set; }
        public DateTimeOffset CTime { get; set; }
        public Microseconds? CUsec { get; set; }
        public DateTimeOffset STime { get; set; }
        public Microseconds? SUsec { get; set; }
        public KrbErrorCode ErrorCode { get; set; }
        public string CRealm { get; set; }
        public PrincipalName CName { get; set; }
        public string ServiceRealm { get; set; }
        public PrincipalName SName { get; set; }
        public string EText { get; set; }
        public byte[] EData { get; set; }
    }
}

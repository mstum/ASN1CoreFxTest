using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace ASN1CoreFxTest
{
    /// <remarks>
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
    /// </remarks>
    internal class KerberosError
    {
        public const int Tag = 30;
        public static readonly Asn1Tag Id = new Asn1Tag(TagClass.Application, 30, isConstructed: true);

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

        public KerberosError(ref AsnReader reader)
        {
            var tag = reader.ReadTagAndLength(out var contentLength, out var bytesRead);
            reader = reader.AdvanceReader(bytesRead);

            if (tag.TagClass != TagClass.Universal || tag.TagValue != (int)UniversalTagNumber.Sequence)
            {
                throw new InvalidOperationException("Not a sequence but " + tag);
            }

            while (reader.HasData)
            {
                tag = reader.ReadTagAndLength(out contentLength, out bytesRead);
                reader = reader.AdvanceReader(bytesRead);

                if (tag.TagClass == TagClass.ContextSpecific)
                {
                    switch (tag.TagValue)
                    {
                        case 0:
                            //         pvno            [0] INTEGER (5),
                            ProtocolVersionNumber = (int)reader.GetInteger();
                            break;
                        case 1:
                            //         msg-type        [1] INTEGER (30),
                            MessageType = (MessageType)(int)reader.GetInteger();
                            break;
                        case 2:
                            //         ctime           [2] KerberosTime OPTIONAL,
                            CTime = reader.GetGeneralizedTime(disallowFractions: true);
                            break;
                        case 3:
                            //         cusec           [3] Microseconds OPTIONAL,
                            var cusec = reader.GetInteger();
                            CUsec = new Microseconds((int)cusec);
                            break;
                        case 4:
                            //         stime           [4] KerberosTime,
                            STime = reader.GetGeneralizedTime(disallowFractions: true);
                            break;
                        case 5:
                            //         susec           [5] Microseconds,
                            var susec = reader.GetInteger();
                            SUsec = new Microseconds((int)susec);
                            break;
                        case 6:
                            //         error-code      [6] Int32,
                            ErrorCode = (KrbErrorCode)(int)reader.GetInteger();
                            break;
                        case 7:
                            //         crealm          [7] Realm OPTIONAL,
                            CRealm = reader.GetCharacterString(new Asn1Tag(UniversalTagNumber.GeneralString), KerberosTags.RealmTag);
                            break;
                        case 8:
                            //         cname           [8] PrincipalName OPTIONAL,
                            CName = new PrincipalName(ref reader);
                            break;
                        case 9:
                            //         realm           [9] Realm -- service realm --,
                            ServiceRealm = reader.GetCharacterString(new Asn1Tag(UniversalTagNumber.GeneralString), KerberosTags.RealmTag);
                            break;
                        case 10:
                            //         sname           [10] PrincipalName -- service name --,
                            SName = new PrincipalName(ref reader);
                            break;
                        case 11:
                            //         e-text          [11] KerberosString OPTIONAL,
                            EText = reader.GetCharacterString(new Asn1Tag(UniversalTagNumber.GeneralString), KerberosTags.KerberosStringTag);
                            break;
                        case 12:
                            //         e-data          [12] OCTET STRING OPTIONAL
                            EData = new byte[contentLength.Value];
                            reader.TryCopyOctetStringBytes(EData, out _);
                            break;
                    }
                }
            }
        }
    }
}

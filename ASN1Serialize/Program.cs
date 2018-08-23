using System;

namespace ASN1Serialize
{
    class Program
    {
        static void Main(string[] args)
        {
            // Explanation below
            var bytes = new byte[] { 0x7e, 0x6a, 0x30, 0x68, 0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x1e, 0xa4, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x38, 0x30, 0x38, 0x30, 0x36, 0x32, 0x30, 0x33, 0x33, 0x30, 0x35, 0x5a, 0xa5, 0x05, 0x02, 0x03, 0x0d, 0xa5, 0x5f, 0xa6, 0x03, 0x02, 0x01, 0x34, 0xa9, 0x14, 0x1b, 0x12, 0x49, 0x4e, 0x54, 0x2e, 0x44, 0x45, 0x56, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x53, 0x2e, 0x4f, 0x52, 0x47, 0xaa, 0x27, 0x30, 0x25, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x1e, 0x30, 0x1c, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x12, 0x49, 0x4e, 0x54, 0x2e, 0x44, 0x45, 0x56, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x53, 0x2e, 0x4f, 0x52, 0x47 };
            var krbError = System.Security.Cryptography.Asn1.AsnSerializer.Deserialize<KerberosError>(bytes, System.Security.Cryptography.Asn1.AsnEncodingRules.DER);
            Console.WriteLine(krbError.ErrorCode);
        }
    }
}
/* bytes:
 * 
 * KRB-ERROR       ::= [APPLICATION 30] SEQUENCE
 * 
 * 0x7e = 01 1 11110 = [Application 30] Constructed
 * 0x6a = Object Length 106 Bytes
 *   0x30 = 00 1 10000 = [Universal 16] Constructed = Sequence
 *   0x68 = Sequence Length 104 Bytes
 *   
 *     pvno            [0] INTEGER (5)
 *     0xa0 = 10 1 00000 = [ContextSpecific 0] Constructed
 *     0x03 = Length 3 Bytes
 *       0x02 = 00 0 00010 = [Universal 2] Primitive = Integer
 *       0x01 = Integer Length 1 Byte
 *       0x05 = Integer Value: 5
 * 
 *     msg-type        [1] INTEGER (30)
 *     0xa1 = 10 1 00001 = [ContextSpecific 1] Constructed
 *     0x03 = Length 3 Bytes
 *       0x02 = 00 0 00010 = [Universal 2] Primitive = Integer
 *       0x01 = Integer Length 1 Byte
 *       0x1e = Integer Value: 30 (MessagtType.KRB_ERROR)
 * 
 *     stime           [4] KerberosTime
 *     0xa4 = 10 1 00100 = [ContextSpecific 4] Constructed
 *     0x11 = Length 17 Bytes
 *       0x18 = 00 0 11000 = [Universal 24] Primitive = GeneralizedTime
 *       0x0f = Length 15 Bytes
 *         0x32 2
 *         0x30 0
 *         0x31 1
 *         0x38 8
 *         0x30 0
 *         0x38 8
 *         0x30 0
 *         0x36 6
 *         0x32 2
 *         0x30 0
 *         0x33 3
 *         0x33 3
 *         0x30 0
 *         0x35 5
 *         0x5a Z
 *     
 *     susec           [5] Microseconds
 *     0xa5 = 10 1 00101 = [ContextSpecific 5] Constructed
 *     0x05 = Length 5 Bytes  
 *       0x02 = 00 0 00010 = [Universal 2] Primitive = Integer
 *       0x03 = Integer Length 3 Byte
 *       0x0d,0xa5,0x5f = 894303 dec
 *       
 *     error-code      [6] Int32
 *     0xa6 = 10 1 00110 = [ContextSpecific 6] Constructed
 *     0x03 = Length 3 Bytes
 *       0x02 = 00 0 00010 = [Universal 2] Primitive = Integer
 *       0x01 = Integer Length 1 Byte
 *       0x34 = 52 (KrbErrorCode.KRB_ERR_RESPONSE_TOO_BIG)
 *     
 *     realm           [9] Realm -- service realm --,
 *     0xa9 = 10 1 01001 = [ContextSpecific 9] Constructed
 *     0x14 = Length 20 Bytes 
 *       0x1b = 00 0 11011 = [Universal 27] Primitive = GeneralString
 *       0x12 = Length 18 Bytes
 *         0x49 I
 *         0x4e N
 *         0x54 T
 *         0x2e .
 *         0x44 D
 *         0x45 E
 *         0x56 V
 *         0x44 D
 *         0x4f O
 *         0x4d M
 *         0x41 A
 *         0x49 I
 *         0x4e N
 *         0x53 S
 *         0x2e .
 *         0x4f O
 *         0x52 R
 *         0x47 G
 *     
 *     sname           [10] PrincipalName -- service name --
 *     0xaa = 10 1 01010 = [ContextSpecific 10] Constructed
 *     0x27 = Length 39 Bytes
 *     
 *       PrincipalName   ::= SEQUENCE
 *       0x30 = 00 1 10000 = [Universal 16] Constructed = Sequence
 *       0x25 = Length 37 Bytes
 *       
 *         name-type       [0] Int32
 *         0xa0 = 10 1 00000 = [ContextSpecific 0] Constructed
 *         0x03 = Length 3 Bytes
 *           0x02 = 00 0 00010 = [Universal 2] Primitive = Integer
 *           0x01 = Length 1 Byte
 *           0x02 = Integer Value: 2 (NameType.NT_SRV_INST)
 *         
 *         name-string     [1] SEQUENCE OF KerberosString
 *         0xa1 = 10 1 00001 = [ContextSpecific 1] Constructed
 *         0x1e = Length 30 Bytes
 *           0x30 = 00 1 10000 = [Universal 16] Constructed = Sequence
 *           0x1c = Length 28 Bytes
 *             0x1b = 00 0 11011 = [Universal 27] Primitive = GeneralString
 *             0x06 = Length 6 Bytes
 *               0x6b k
 *               0x72 r
 *               0x62 b
 *               0x74 t
 *               0x67 g
 *               0x74 t
 *               
 *             0x1b = 00 0 11011 = [Universal 27] Primitive = GeneralString
 *             0x12 = Length 18 Bytes
 *               0x49 I
 *               0x4e N
 *               0x54 T
 *               0x2e .
 *               0x44 D
 *               0x45 E
 *               0x56 V
 *               0x44 D
 *               0x4f O
 *               0x4d M
 *               0x41 A
 *               0x49 I
 *               0x4e N
 *               0x53 S
 *               0x2e .
 *               0x4f O
 *               0x52 R
 *               0x47 G
 */

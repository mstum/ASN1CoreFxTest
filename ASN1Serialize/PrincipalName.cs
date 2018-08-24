using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace ASN1Serialize
{
    /// <summary>
    /// PrincipalName   ::= SEQUENCE {
    ///         name-type       [0] Int32,
    ///         name-string     [1] SEQUENCE OF KerberosString
    /// }
    /// </summary>
    [SequenceOf]
    [StructLayout(LayoutKind.Sequential)]
    internal sealed class PrincipalName
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

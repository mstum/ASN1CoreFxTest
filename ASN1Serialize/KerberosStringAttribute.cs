using System.Security.Cryptography.Asn1;

namespace ASN1Serialize
{
    internal class KerberosStringAttribute : GeneralStringAttribute
    {
        public KerberosStringAttribute()
            : base(UniversalTagNumber.IA5String)
        {
        }
    }

    internal class RealmAttribute : KerberosStringAttribute
    {
    }
}

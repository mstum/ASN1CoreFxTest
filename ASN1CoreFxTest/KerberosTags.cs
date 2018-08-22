using System;
using System.Collections.Generic;
using System.Text;

namespace ASN1CoreFxTest
{
    internal static class KerberosTags
    {
        // Encoded as GeneralString!
        internal const UniversalTagNumber KerberosStringTag = UniversalTagNumber.IA5String;
        internal const UniversalTagNumber RealmTag = KerberosStringTag;
    }
}

using System;
using System.Collections.Generic;
using System.Text;

namespace ASN1CoreFxTest
{
    /// PrincipalName   ::= SEQUENCE {
    ///         name-type       [0] Int32,
    ///         name-string     [1] SEQUENCE OF KerberosString
    /// }
    internal class PrincipalName
    {
        public NameType Type { get; set; }
        public string[] Name { get; set; }

        public PrincipalName(ref AsnReader reader)
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
                            Type = (NameType)(int)reader.GetInteger();
                            break;
                        case 1:
                            reader = reader.ReadSequence();
                            var names = new List<string>();
                            while (reader.HasData)
                            {
                                names.Add(reader.GetCharacterString(new Asn1Tag(UniversalTagNumber.GeneralString), KerberosTags.KerberosStringTag));
                            }
                            Name = names.ToArray();
                            break;
                    }
                }
            }
        }
    }
}

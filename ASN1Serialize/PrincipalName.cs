namespace ASN1Serialize
{
    /// <summary>
    /// PrincipalName   ::= SEQUENCE {
    ///         name-type       [0] Int32,
    ///         name-string     [1] SEQUENCE OF KerberosString
    /// }
    /// </summary>
    internal class PrincipalName
    {
        public NameType Type { get; set; }
        public string[] Name { get; set; }
    }
}

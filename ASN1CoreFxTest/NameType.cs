using System;
using System.Collections.Generic;
using System.Text;

namespace ASN1CoreFxTest
{
    public enum NameType
    {
        NT_UNKNOWN = 0,
        NT_PRINCIPAL = 1,
        NT_SRV_INST = 2,
        NT_SRV_HST = 3,
        NT_SRV_XHST = 4,
        NT_UID = 5,
        NT_X500_PRINCIPAL = 6,
        NT_SMTP_NAME = 7,
        NT_ENTERPRISE = 10,
        NT_WELLKNOWN = 11 // RFC 6111
    }
}

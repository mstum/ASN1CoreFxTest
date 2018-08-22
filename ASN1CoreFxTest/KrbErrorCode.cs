using System.ComponentModel;

namespace ASN1CoreFxTest
{
    public enum KrbErrorCode
    {
        [Description("No error")]
        KDC_ERR_NONE = 0,

        [Description("Client's entry in database has expired")]
        KDC_ERR_NAME_EXP = 1,

        [Description("Server's entry in database has expired")]
        KDC_ERR_SERVICE_EXP = 2,

        [Description("Requested protocol version number not supported")]
        KDC_ERR_BAD_PVNO = 3,

        [Description("Client's key encrypted in old master key")]
        KDC_ERR_C_OLD_MAST_KVNO = 4,

        [Description("Server's key encrypted in old master key")]
        KDC_ERR_S_OLD_MAST_KVNO = 5,

        [Description("Client not found in Kerberos database")]
        KDC_ERR_C_PRINCIPAL_UNKNOWN = 6,

        [Description("Server not found in Kerberos database")]
        KDC_ERR_S_PRINCIPAL_UNKNOWN = 7,

        [Description("Multiple principal entries in database")]
        KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8,

        [Description("The client or server has a null key")]
        KDC_ERR_NULL_KEY = 9,

        [Description("Ticket not eligible for postdating")]
        KDC_ERR_CANNOT_POSTDATE = 10,

        [Description("Requested starttime is later than end time")]
        KDC_ERR_NEVER_VALID = 11,

        [Description("KDC policy rejects request")]
        KDC_ERR_POLICY = 12,

        [Description("KDC cannot accommodate requested option")]
        KDC_ERR_BADOPTION = 13,

        [Description("KDC has no support for encryption type")]
        KDC_ERR_ETYPE_NOSUPP = 14,

        [Description("KDC has no support for checksum type")]
        KDC_ERR_SUMTYPE_NOSUPP = 15,

        [Description("KDC has no support for padata type")]
        KDC_ERR_PADATA_TYPE_NOSUPP = 16,

        [Description("KDC has no support for transited type")]
        KDC_ERR_TRTYPE_NOSUPP = 17,

        [Description("Clients credentials have been revoked")]
        KDC_ERR_CLIENT_REVOKED = 18,

        [Description("Credentials for server have been revoked")]
        KDC_ERR_SERVICE_REVOKED = 19,

        [Description("TGT has been revoked")]
        KDC_ERR_TGT_REVOKED = 20,

        [Description("Client not yet valid; try again later")]
        KDC_ERR_CLIENT_NOTYET = 21,

        [Description("Server not yet valid; try again later")]
        KDC_ERR_SERVICE_NOTYET = 22,

        [Description("Password has expired; change password to reset")]
        KDC_ERR_KEY_EXPIRED = 23,

        [Description("Pre-authentication information was invalid")]
        KDC_ERR_PREAUTH_FAILED = 24,

        [Description("Additional pre-authentication required")]
        KDC_ERR_PREAUTH_REQUIRED = 25,

        [Description("Requested server and ticket don't match")]
        KDC_ERR_SERVER_NOMATCH = 26,

        [Description("Server principal valid for user2user only")]
        KDC_ERR_MUST_USE_USER2USER = 27,

        [Description("KDC Policy rejects transited path")]
        KDC_ERR_PATH_NOT_ACCEPTED = 28,

        [Description("A service is not available")]
        KDC_ERR_SVC_UNAVAILABLE = 29,

        [Description("Integrity check on decrypted field failed")]
        KRB_AP_ERR_BAD_INTEGRITY = 31,

        [Description("Ticket expired")]
        KRB_AP_ERR_TKT_EXPIRED = 32,

        [Description("Ticket not yet valid")]
        KRB_AP_ERR_TKT_NYV = 33,

        [Description("Request is a replay")]
        KRB_AP_ERR_REPEAT = 34,

        [Description("The ticket isn't for us")]
        KRB_AP_ERR_NOT_US = 35,

        [Description("Ticket and authenticator don't match")]
        KRB_AP_ERR_BADMATCH = 36,

        [Description("Clock skew too great")]
        KRB_AP_ERR_SKEW = 37,

        [Description("Incorrect net address")]
        KRB_AP_ERR_BADADDR = 38,

        [Description("Protocol version mismatch")]
        KRB_AP_ERR_BADVERSION = 39,

        [Description("Invalid msg type")]
        KRB_AP_ERR_MSG_TYPE = 40,

        [Description("Message stream modified")]
        KRB_AP_ERR_MODIFIED = 41,

        [Description("Message out of order")]
        KRB_AP_ERR_BADORDER = 42,

        [Description("Specified version of key is not available")]
        KRB_AP_ERR_BADKEYVER = 44,

        [Description("Service key not available")]
        KRB_AP_ERR_NOKEY = 45,

        [Description("Mutual authentication failed")]
        KRB_AP_ERR_MUT_FAIL = 46,

        [Description("Incorrect message direction")]
        KRB_AP_ERR_BADDIRECTION = 47,

        [Description("Alternative authentication method required")]
        KRB_AP_ERR_METHOD = 48,

        [Description("Incorrect sequence number in message")]
        KRB_AP_ERR_BADSEQ = 49,

        [Description("Inappropriate type of checksum in message")]
        KRB_AP_ERR_INAPP_CKSUM = 50,

        [Description("Policy rejects transited path")]
        KRB_AP_PATH_NOT_ACCEPTED = 51,

        [Description("Response too big for UDP; retry with TCP")]
        KRB_ERR_RESPONSE_TOO_BIG = 52,

        [Description("Generic error (description in e-text)")]
        KRB_ERR_GENERIC = 60,

        [Description("Field is too long for this implementation")]
        KRB_ERR_FIELD_TOOLONG = 61,

        [Description("Reserved for PKINIT")]
        KDC_ERROR_CLIENT_NOT_TRUSTED = 62,

        [Description("Reserved for PKINIT")]
        KDC_ERROR_KDC_NOT_TRUSTED = 63,

        [Description("Reserved for PKINIT")]
        KDC_ERROR_INVALID_SIG = 64,

        [Description("Reserved for PKINIT")]
        KDC_ERR_KEY_TOO_WEAK = 65,

        [Description("Reserved for PKINIT")]
        KDC_ERR_CERTIFICATE_MISMATCH = 66,

        [Description("No TGT available to validate USER-TO-USER")]
        KRB_AP_ERR_NO_TGT = 67,

        [Description("Reserved for future use")]
        KDC_ERR_WRONG_REALM = 68,

        [Description("Ticket must be for USER-TO-USER")]
        KRB_AP_ERR_USER_TO_USER_REQUIRED = 69,

        [Description("Reserved for PKINIT")]
        KDC_ERR_CANT_VERIFY_CERTIFICATE = 70,

        [Description("Reserved for PKINIT")]
        KDC_ERR_INVALID_CERTIFICATE = 71,

        [Description("Reserved for PKINIT")]
        KDC_ERR_REVOKED_CERTIFICATE = 72,

        [Description("Reserved for PKINIT")]
        KDC_ERR_REVOCATION_STATUS_UNKNOWN = 73,

        [Description("Reserved for PKINIT")]
        KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74,

        [Description("Reserved for PKINIT")]
        KDC_ERR_CLIENT_NAME_MISMATCH = 75,

        [Description("Reserved for PKINIT")]
        KDC_ERR_KDC_NAME_MISMATCH = 76
    }
}

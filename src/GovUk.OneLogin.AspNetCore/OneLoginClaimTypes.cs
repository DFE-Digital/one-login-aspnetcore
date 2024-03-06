namespace GovUk.OneLogin.AspNetCore;

/// <summary>
/// Defines constants for the claim types supported by One Login.
/// </summary>
public static class OneLoginClaimTypes
{
    /// <summary>
    /// The claim type of the core identity claim.
    /// </summary>
    public const string CoreIdentity = "https://vocab.account.gov.uk/v1/coreIdentityJWT";

    /// <summary>
    /// The claim type of the address claim.
    /// </summary>
    public const string Address = "https://vocab.account.gov.uk/v1/address";

    /// <summary>
    /// The claim type of the passport claim.
    /// </summary>
    public const string Passport = "https://vocab.account.gov.uk/v1/passport";

    /// <summary>
    /// The claim type of the driving licence claim.
    /// </summary>
    public const string DrivingLicence = "https://vocab.account.gov.uk/v1/drivingPermit";

    /// <summary>
    /// The claim type of the National Insurance number claim.
    /// </summary>
    public const string NationalInsuranceNumber = "https://vocab.account.gov.uk/v1/socialSecurityRecord";
}

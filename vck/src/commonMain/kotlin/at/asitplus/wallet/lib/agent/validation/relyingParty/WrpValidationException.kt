package at.asitplus.wallet.lib.agent.validation.relyingParty

/**
 * Reasons why a request could not be validated for a relying party at all, as opposed to the findings reported in
 * the validation results, so that wallets can tell them apart.
 */
sealed class WrpValidationException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause) {

    /** The request carries no registration certificate, e.g. no `verifier_info` with a `registration_cert`. */
    class RegistrationCertificateMissing(message: String) : WrpValidationException(message)

    /** The request carries a registration certificate that cannot be parsed, or more than one. */
    class RegistrationCertificateMalformed(message: String, cause: Throwable? = null) :
        WrpValidationException(message, cause)

    /** Registration certificates of this kind of request cannot be validated, e.g. of an unsigned request. */
    class UnsupportedRequest(message: String) : WrpValidationException(message)
}

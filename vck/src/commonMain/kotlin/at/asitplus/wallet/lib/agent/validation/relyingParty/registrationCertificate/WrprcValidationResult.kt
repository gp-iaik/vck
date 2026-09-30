package at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate

import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate

data class WrprcValidationResult(
    val certificateValidation: Map<WrpRegistrationCertificate, WrpRegistrationCertificateValidation?>,
    val requestDataValidation: RequestDataValidation
)


data class WrpRegistrationCertificateValidation(
    val validHeader: Boolean,
    val validSignature: Boolean,
    val validChain: Boolean,
    val validPayload: Boolean,
    val validLinkage: Boolean,
    val validStatusList: Boolean,
    /**
     * Whether the status could be obtained at all, e.g. `false` for an unreachable status list, in which case
     * [validStatusList] is `false` without the certificate having been revoked or suspended.
     */
    val statusListResolved: Boolean = true,
) {
    fun isValid() = validHeader && validSignature && validChain && validPayload && validLinkage && validStatusList
}

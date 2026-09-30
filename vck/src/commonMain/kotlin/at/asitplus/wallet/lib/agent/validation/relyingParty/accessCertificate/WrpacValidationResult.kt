package at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate

import at.asitplus.signum.indispensable.pki.X509Certificate

data class WrpacValidationResult(
    val chain: List<X509Certificate>,
    /** Identifier of the relying party, or `null` if the access certificate carries none. */
    val identifierResult: WrpacIdentifier?,
    /** Whether the `client_id` of the request is bound to the access certificate, see [linkageError]. */
    val validLinkage: Boolean,
    /** Whether the certificate chain is valid and anchored in the trusted certificates, see [chainError]. */
    val validChain: Boolean = true,
    val linkageError: Throwable? = null,
    val chainError: Throwable? = null,
) {
    fun isValid() = identifierResult != null && validLinkage && validChain
}

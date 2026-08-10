package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.OpenIdConstants
import at.asitplus.wallet.lib.etsi.Success

/**
 * Handles authenticating the OAuth 2.0 client for an OAuth 2.0 authorization server,
 * see [SimpleAuthorizationService] and subclasses of this interface.
 */
interface ClientAuthenticationService {

    val supportedAuthMethods: Set<String>?
    val supportedSigningAlgs: Set<String>?
    val supportedPopSigningAlgs: Set<String>?
    val supportedPopMethods: Set<OpenIdConstants.ClientAttestationPopMethod>?

    /** Provide a fresh challenge for attestation PoPs. */
    suspend fun getAttestationChallenge(): String?

    /** Authenticates the client by some data in the request. */
    suspend fun authenticateClient(
        httpRequest: RequestInfo?,
        clientId: String?,
    ): KmmResult<Success>
}

/** Does not verify the client authentication at all */
object NoopClientAuthenticationService : ClientAuthenticationService {
    override val supportedAuthMethods: Set<String>?
        get() = null
    override val supportedSigningAlgs: Set<String>?
        get() = null
    override val supportedPopSigningAlgs: Set<String>?
        get() = null
    override val supportedPopMethods: Set<OpenIdConstants.ClientAttestationPopMethod>
        get() = setOf(OpenIdConstants.ClientAttestationPopMethod.None)

    override suspend fun getAttestationChallenge(): String? = null

    override suspend fun authenticateClient(
        httpRequest: RequestInfo?,
        clientId: String?
    ): KmmResult<Success> = catching {
        Success
    }
}

package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithCnf
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithCnfFun
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService.Companion.DEFAULT_WALLET_ATTESTATION_ALGORITHMS
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.*
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes


/**
 * Client authentication service for an OAuth2.0 AS, based on Attestation-Based Client Authentication.
 *
 * Implemented from:
 * * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
 * * [EUDI TS3 Wallet Unit Attestation 1.5.2](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
 */
class AttestationBasedClientAuthenticationService @JvmOverloads constructor(
    /**
     * Used to verify client attestation JWTs. Client attestations are required to carry an `x5c`, so pass
     * [at.asitplus.wallet.lib.jws.VerifyJwsObjectTrustedCertificate] with the certificates of the trusted wallet
     * providers to establish trust in the attestation. The default only verifies the attestation against the
     * certificate it carries itself, i.e. it makes no trust decision.
     */
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    /** Used to verify client attestation JWTs */
    private val verifyJwsSignatureWithCnf: VerifyJwsSignatureWithCnfFun = VerifyJwsSignatureWithCnf(),
    /** Clock used to verify WIA and WIA PoP timestamps. */
    private val clock: Clock = Clock.System,
    /** Time leeway for verification of WIA and WIA PoP timestamps. */
    private val timeLeeway: Duration = 5.minutes,
    /** Maximum age of WIA PoP JWTs. */
    private val maxAgePoP: Duration = 10.minutes,
    /** Identifier of this authorization server, to verify `aud` of incoming PoP JWTs. */
    private val issuerIdentifier: String? = null,
    /** Used for [OAuth2AuthorizationServerMetadata.clientAttestationSigningAlgValuesSupportedStrings] */
    private val supportedSigningAlgorithms: Set<JwsAlgorithm.Signature> = DEFAULT_WALLET_ATTESTATION_ALGORITHMS,
    /** Service used to create challenges for the clients to use in PoP JWT. */
    private val nonceService: NonceService = DefaultNonceService(),
) : ClientAuthenticationService {
    override val supportedAuthMethods: Set<String>
        get() = setOf(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH)

    override val supportedPopSigningAlgs: Set<String>
        get() = supportedSigningAlgorithms.map { it.identifier }.toSet()

    override val supportedSigningAlgs: Set<String>
        get() = supportedSigningAlgorithms.map { it.identifier }.toSet()

    override val supportedPopMethods: Set<OpenIdConstants.ClientAttestationPopMethod>
        get() = setOf(OpenIdConstants.ClientAttestationPopMethod.AttestationPopJwt)

    override suspend fun getAttestationChallenge(): String = nonceService.provideNonce()

    /**
     * Authenticates the client as defined from a client attestation JWT.
     */
    override suspend fun authenticateClient(
        httpRequest: RequestInfo?,
        clientId: String?,
        validatedClientKey: JsonWebKey?,
    ): KmmResult<AuthenticatedClient> = catching {
        val instanceAttestation = httpRequest?.clientAttestation
            ?: throw InvalidClient("client attestation header missing")

        val instanceAttestationPopJwt = httpRequest.clientAttestationPop
            ?: throw InvalidClient("client attestation pop header missing")


        instanceAttestation.validateWalletInstanceAttestation(clientId)
        verifyJwsObject(instanceAttestation.jws).getOrElse {
            throw InvalidClient("client attestation JWT not verified", it)
        }

        val cnf = instanceAttestation.payload.confirmationClaim
            ?: throw InvalidClient("client attestation has no cnf")
        if (!verifyJwsSignatureWithCnf(instanceAttestationPopJwt.jws, cnf)) {
            throw InvalidClient("client attestation PoP JWT not verified")
        }

        // TODO use validatedClientKey
        instanceAttestationPopJwt.validateWalletInstanceAttestationPop(instanceAttestation.payload.subject)
        AuthenticatedClient(
            clientId = instanceAttestation.payload.subject
                ?: clientId // validation above should have caught that, but the compiler did not
                ?: throw InvalidClient("No client_id given"),
            publicKey = cnf.jsonWebKey?.toCryptoPublicKey()?.getOrThrow()
        )
    }

    private fun JwsCompactTyped<JsonWebToken>.validateWalletInstanceAttestation(clientId: String?) {
        if (jws.jwsHeader.type != JwsContentTypeConstants.CLIENT_ATTESTATION_JWT) {
            throw InvalidClient("invalid client attestation typ: ${jws.jwsHeader.type}")
        }
        if (jws.jwsHeader.certificateChain.isNullOrEmpty()) {
            throw InvalidClient("client attestation has no x5c")
        }
        if (jws.jwsHeader.algorithm !is JwsAlgorithm.Signature ||
            jws.jwsHeader.algorithm !in supportedSigningAlgorithms
        ) {
            throw InvalidClient("unsupported client attestation alg: ${jws.jwsHeader.algorithm}")
        }
        if (payload.subject == null) {
            throw InvalidClient("client attestation has no sub")
        }
        if (clientId != null && payload.subject != clientId) {
            throw InvalidClient("subject not equal to client_id")
        }
        val issuedAt = payload.issuedAt ?: throw InvalidClient("client attestation has no iat")
        val expiration = payload.expiration ?: throw InvalidClient("client attestation has no exp")
        if (issuedAt > (clock.now() + timeLeeway)) {
            throw UseFreshAttestation("client attestation iat in future: $issuedAt")
        }
        if (expiration < (clock.now() - timeLeeway)) {
            throw UseFreshAttestation("client attestation expired: $expiration")
        }
        if (expiration - issuedAt >= 24.hours) {
            throw UseFreshAttestation("client attestation lifetime must be less than 24 hours")
        }
        if (payload.walletName.isNullOrBlank()) {
            throw InvalidClient("client attestation has no wallet_name")
        }
        if (payload.walletVersion.isNullOrBlank()) {
            throw InvalidClient("client attestation has no wallet_version")
        }
        if (payload.walletSolutionCertificationInformation.isNullOrBlank()) {
            throw InvalidClient("client attestation has no wallet_solution_certification_information")
        }
        val clientStatus = payload.clientStatus ?: throw InvalidClient("client attestation has no client_status")
        if (clientStatus.expiration < (clock.now() - timeLeeway)) {
            throw InvalidClient("client_status expiration in past: ${clientStatus.expiration}")
        }
        val confirmationKey = payload.confirmationClaim?.jsonWebKey?.toCryptoPublicKey()?.getOrNull()
            ?: throw InvalidClient("client attestation has no cnf")
        if (confirmationKey !is CryptoPublicKey.EC && confirmationKey !is CryptoPublicKey.RSA) {
            throw InvalidClient("client attestation confirmation key is not asymmetric")
        }
    }

    private suspend fun JwsCompactTyped<JsonWebToken>.validateWalletInstanceAttestationPop(
        attestationSubject: String?
    ) {
        if (jws.jwsHeader.type != JwsContentTypeConstants.CLIENT_ATTESTATION_POP_JWT) {
            throw InvalidClient("invalid client attestation PoP typ: ${jws.jwsHeader.type}")
        }
        if (jws.jwsHeader.algorithm !is JwsAlgorithm.Signature ||
            jws.jwsHeader.algorithm !in supportedSigningAlgorithms
        ) {
            throw InvalidClient("unsupported client attestation PoP alg: ${jws.jwsHeader.algorithm}")
        }
        if (issuerIdentifier != null && payload.audience != issuerIdentifier) {
            throw InvalidClient(
                "client attestation PoP aud '${payload.audience}' does not match issuer '$issuerIdentifier'"
            )
        }
        val issuedAt = payload.issuedAt
            ?: throw InvalidClient("client attestation PoP has no iat")
        val expiration = payload.expiration // not required!
        if (issuedAt > (clock.now() + timeLeeway)) {
            throw InvalidClient("client attestation PoP iat in future: $issuedAt")
        }
        if (issuedAt < (clock.now() - maxAgePoP - timeLeeway)) {
            throw InvalidClient("client attestation PoP issued too long ago: $issuedAt")
        }
        if (expiration != null && expiration < (clock.now() - timeLeeway)) {
            throw InvalidClient("client attestation PoP expired: $expiration")
        }
        if (payload.jwtId == null) {
            throw InvalidClient("client attestation PoP has no jti")
        }
        if (payload.issuer != null && attestationSubject != null && payload.issuer != attestationSubject) {
            throw InvalidClient("client attestation PoP issuer not equal to attestation subject")
        }
        if (payload.nonce == null && payload.challenge == null) {
            throw UseAttestationChallenge(nonceService.provideNonce(), "client attestation PoP missing challenge/nonce")
        }
        payload.nonce?.let { nonce ->
            if (!nonceService.verifyAndRemoveNonce(nonce)) {
                throw UseAttestationChallenge(nonceService.provideNonce(), "client attestation PoP nonce invalid")
            }
        } ?: payload.challenge?.let { challenge ->
            if (!nonceService.verifyAndRemoveNonce(challenge)) {
                throw UseAttestationChallenge(nonceService.provideNonce(), "client attestation PoP challenge invalid")
            }
        } ?: throw UseAttestationChallenge(nonceService.provideNonce(), "client attestation PoP challenge missing")
    }

}

package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.signerFor
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import kotlin.coroutines.cancellation.CancellationException

/**
 * Creates one ephemeral encryption key for every authentication request, and recovers it once the response to that
 * request comes in, as required by
 * [OpenID4VP 1.0, 8.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-encrypted-responses),
 * and by
 * [OpenID4VC HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html).
 *
 * Private keys are kept PKCS#8-PEM-encoded in [identifierToPrivateKeyPem], so that deployments running several
 * instances can synchronize them between the instance that created the request and the instance receiving the response,
 * by passing the same sort of [MapStore] implementation they use for the other stores of e.g. `OpenId4VpVerifier`.
 * Note that keys of abandoned flows are never consumed, so entries
 * need to be evicted eventually, which [DefaultMapStore] does after its `lifetime`.
 */
class EphemeralEncryptionKeyService(
    private val identifierToPrivateKeyPem: MapStore<String, String> = DefaultMapStore(),
) {

    /**
     * Creates and stores a fresh key, to be advertised in the client metadata of a single authentication request.
     * Pass an [identifier] to look the key up by something other than its own random [KeyMaterial.identifier],
     * e.g. by the `state` of the request, when the response won't carry a key identifier.
     */
    @OptIn(SecretExposure::class)
    suspend fun createKey(identifier: String? = null): KeyMaterial =
        (identifier?.let { EphemeralKeyWithoutCert(customKeyId = it) } ?: EphemeralKeyWithoutCert()).also {
            identifierToPrivateKeyPem.put(
                it.identifier,
                it.key.exportPrivateKey().getOrThrow().encodeToPEM().getOrThrow()
            )
        }

    /**
     * Loads and removes the key stored under [identifier], i.e. every key decrypts at most one response, matching the
     * single-use lifecycle of the authentication request it belongs to.
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun consumeKey(identifier: String): KeyMaterial? =
        identifierToPrivateKeyPem.remove(identifier)?.let { pem ->
            val privateKey = CryptoPrivateKey.decodeFromPem(pem).getOrThrow()
            require(privateKey is CryptoPrivateKey.EC.WithPublicKey) { "Not an EC private key: $identifier" }
            EphemeralEncryptionKey(
                signer = SignatureAlgorithm.ECDSAwithSHA256.signerFor(privateKey).getOrThrow(),
                identifier = identifier,
            )
        }
}

/** Key material recovered from [EphemeralEncryptionKeyService], used for key agreement only. */
private class EphemeralEncryptionKey(signer: Signer, identifier: String) : SignerBasedKeyMaterial(signer, identifier) {
    override suspend fun getCertificate(): X509Certificate? = null
}

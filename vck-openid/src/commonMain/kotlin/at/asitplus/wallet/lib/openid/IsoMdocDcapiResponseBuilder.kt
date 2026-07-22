package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
import at.asitplus.dcapi.DCAPIInfo
import at.asitplus.dcapi.EncryptedResponse
import at.asitplus.dcapi.EncryptedResponseData
import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.serializeHttpHttpsOrigin
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.supreme.asymmetric.HPKE
import at.asitplus.wallet.lib.agent.CreatePresentationResult
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters
import at.asitplus.wallet.lib.cbor.CoseHeaderNone
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.data.CredentialPresentation
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray

/** Low-level ISO/IEC 18013-7 Annex C device-response construction used by [Iso180137AnnexCHolder]. */
object IsoMdocDcapiResponseBuilder {

    private val hpke = HPKE(
        HPKE.KEM.DHKEM_P256_HKDF_SHA256,
        HPKE.KDF.HKDF_SHA256,
        HPKE.AEAD.AES_128_GCM,
    )

    /** Builds the DC API session transcript bound to the request encryption information and calling origin. */
    fun sessionTranscriptFor(isoMdocWalletRequest: RequestParametersFrom.IsoMdocDcApi): SessionTranscript {
        val isoMdocRequest = isoMdocWalletRequest.parameters.isoMdocRequest
        val callingOrigin = isoMdocWalletRequest.callingOrigin.serializeHttpHttpsOrigin()
            ?: throw IllegalArgumentException("Invalid calling origin")
        val hash = coseCompliantSerializer.encodeToByteArray(
            DCAPIInfo(isoMdocRequest.encryptionInfo, callingOrigin)
        ).sha256()
        val handover = DCAPIHandover(type = TYPE_DCAPI, hash = hash)
        return SessionTranscript.forDcApi(handover)
    }

    /** Creates the device response, applies device authentication, and HPKE-encrypts it for the verifier. */
    suspend fun buildEncryptedResponse(
        credentialPresentation: CredentialPresentation.PresentationExchangePresentation,
        isoMdocWalletRequest: RequestParametersFrom.IsoMdocDcApi,
        keyMaterial: KeyMaterial,
        holder: Holder,
        signDeviceAuthDetached: SignCoseDetachedFun<ByteArray> =
            SignCoseDetached(keyMaterial, CoseHeaderNone(), CoseHeaderNone()),
    ): EncryptedResponse {
        val sessionTranscript = sessionTranscriptFor(isoMdocWalletRequest)
        val isoMdocRequest = isoMdocWalletRequest.parameters.isoMdocRequest
        val callingOrigin = isoMdocWalletRequest.callingOrigin.serializeHttpHttpsOrigin()
            ?: throw IllegalArgumentException("Invalid calling origin")

        val presentationResult = holder.createPresentation(
            request = PresentationRequestParameters(
                nonce = isoMdocRequest.encryptionInfo.encryptionParameters.nonce
                    ?.encodeToString(Base64UrlStrict) ?: throw IllegalArgumentException("no nonce"),
                audience = callingOrigin,
                calcIsoDeviceSignaturePlain = { input ->
                    val deviceAuthentication = DeviceAuthentication(
                        type = DeviceAuthentication.TYPE,
                        sessionTranscript = sessionTranscript,
                        docType = input.docType,
                        namespaces = input.deviceNameSpaceBytes
                    )

                    val deviceAuthenticationBytes = coseCompliantSerializer
                        .encodeToByteArray(ByteStringWrapper(deviceAuthentication))
                        .wrapInCborTag(24)
                    Napier.d("Device authentication signature input is ${deviceAuthenticationBytes.toHexString()}")
                    signDeviceAuthDetached(null, null, deviceAuthenticationBytes, ByteArraySerializer())
                        .getOrElse { e ->
                            Napier.w("Could not create DeviceAuth for presentation", e)
                            throw PresentationException(e)
                        }
                },
                returnOneDeviceResponse = true,
            ),
            credentialPresentation = credentialPresentation,
        )

        val presentation =
            presentationResult.getOrThrow() as PresentationResponseParameters.PresentationExchangeParameters

        val deviceResponse = when (val result = presentation.presentationResults.singleOrNull()
            ?: throw PresentationException(
                IllegalStateException("Annex C presentation must return exactly one device response")
            )) {
            is CreatePresentationResult.DeviceResponse -> result.deviceResponse
            else -> throw PresentationException(IllegalStateException("Must be a device response"))
        }
        val deviceResponseSerialized = coseCompliantSerializer.encodeToByteArray(deviceResponse)

        val encryptionParameters = isoMdocRequest.encryptionInfo.encryptionParameters

        val publicKey = try {
            encryptionParameters.recipientPublicKey.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC
        } catch (e: Throwable) {
            Napier.e("Could not extract public key", e)
            throw IllegalArgumentException("Could not extract public key")
        }
        val encodedSessionTranscript = coseCompliantSerializer.encodeToByteArray(sessionTranscript)
        val sealed = hpke.SealBase(
            pkR = publicKey,
            info = encodedSessionTranscript,
            aad = ByteArray(0),
            pt = deviceResponseSerialized,
        )
        val encryptedResponseData = EncryptedResponseData(
            enc = sealed.encapsulatedSecret,
            cipherText = sealed.ciphertext
        )
        return EncryptedResponse(TYPE_DCAPI, encryptedResponseData)
    }
}

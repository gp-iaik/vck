package at.asitplus.dcapi

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.encodeToByteArray

/**
 * Encodes the encrypted Annex C response payload for Apple's ISO 18013 mobile document response API.
 *
 * Unlike [toAndroidDcApiResponseJson], this returns only the CBOR-encoded [DCAPIResponse.response] expected by the
 * iOS API, not the complete [DigitalCredentialInterface] envelope.
 *
 * @throws IllegalArgumentException if this is an OpenID4VP response rather than an [IsoMdocResponse].
 */
fun DigitalCredentialInterface.toIosIsoMdocResponseBytes(): ByteArray {
    val isoMdocResponse = this as? IsoMdocResponse
        ?: throw IllegalArgumentException("iOS mobile document responses require ISO 18013-7 Annex C")
    return coseCompliantSerializer.encodeToByteArray(isoMdocResponse.data.response)
}

package at.asitplus.wallet.sdjwt

import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SdJwtTypeMetadataTypeDisplayInformationRenderingMetadataSimpleBackgroundImageMetadata(
    @SerialName(SerialNames.URI)
    val uri: Rfc3986UniformResourceIdentifier,
    @SerialName(SerialNames.URI_INTEGRITY)
    val uriIntegrity: W3cSubresourceIntegrityMetadata? = null,
) {
    object SerialNames {
        const val URI = "uri"
        const val URI_INTEGRITY = "uri#integrity"
    }
}
package at.asitplus.wallet.sdjwt

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SdJwtTypeMetadata(
    @SerialName(SdJwtTypeMetadataDefinition.SerialNames.VCT)
    val vct: SdJwtVcType,
    @SerialName(SdJwtTypeMetadataDefinition.SerialNames.NAME)
    val name: String? = null,
    @SerialName(SdJwtTypeMetadataDefinition.SerialNames.DESCRIPTION)
    val description: String? = null,
    @SerialName(SdJwtTypeMetadataDefinition.SerialNames.DISPLAY)
    val display: SdJwtTypeMetadataTypeDisplayInformationList? = null,
    @SerialName(SdJwtTypeMetadataDefinition.SerialNames.CLAIMS)
    val claims: SdJwtTypeMetadataClaimInformationList? = null,
)
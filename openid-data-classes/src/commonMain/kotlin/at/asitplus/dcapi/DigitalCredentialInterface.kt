package at.asitplus.dcapi

import at.asitplus.dcapi.DigitalCredentialInterface.SerialNames
import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import at.asitplus.openid.AuthenticationResponseParameters
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

@Serializable
@JsonClassDiscriminator(SerialNames.PROTOCOL)
sealed class DigitalCredentialInterface {
    abstract val protocol: ExchangeProtocolIdentifier
    abstract val origin: String?

    object SerialNames {
        const val DATA = "data"
        const val PROTOCOL = "protocol"
        const val ORIGIN = "origin"
        const val ORG_ISO_MDOC = ExchangeProtocolIdentifier.ORG_ISO_MDOC
        const val OPENID4VP_V1_UNSIGNED = ExchangeProtocolIdentifier.OPENID4VP_V1_UNSIGNED
        const val OPENID4VP_V1_SIGNED = ExchangeProtocolIdentifier.OPENID4VP_V1_SIGNED
        const val OPENID4VP_V1_MULTISIGNED = ExchangeProtocolIdentifier.OPENID4VP_V1_MULTISIGNED
    }
}

@Serializable
@SerialName(SerialNames.ORG_ISO_MDOC)
data class IsoMdocResponse(
    @SerialName(SerialNames.DATA)
    val data: DCAPIResponse,
    @SerialName(SerialNames.ORIGIN)
    override val origin: String? = null,
) : DigitalCredentialInterface() {
    override val protocol: ExchangeProtocolIdentifier
        get() = ExchangeProtocolIdentifier.IsoMdocAnnexC
}


@Serializable
@JsonClassDiscriminator(SerialNames.PROTOCOL)
sealed interface OpenId4VpResponse {
    val protocol: ExchangeProtocolIdentifier
    val data: AuthenticationResponseParameters
    val origin: String?
}

@Serializable
@SerialName(SerialNames.OPENID4VP_V1_SIGNED)
data class OpenId4VpResponseSigned(
    @SerialName(SerialNames.DATA)
    override val data: AuthenticationResponseParameters,
    @SerialName(SerialNames.ORIGIN)
    override val origin: String? = null,
) : DigitalCredentialInterface(), OpenId4VpResponse {
    override val protocol: ExchangeProtocolIdentifier
        get() = ExchangeProtocolIdentifier.OpenId4VpV1Signed
}

@Serializable
@SerialName(SerialNames.OPENID4VP_V1_MULTISIGNED)
data class OpenId4VpResponseMultiSigned(
    @SerialName(SerialNames.DATA)
    override val data: AuthenticationResponseParameters,
    @SerialName(SerialNames.ORIGIN)
    override val origin: String? = null,
) : DigitalCredentialInterface(), OpenId4VpResponse {
    override val protocol: ExchangeProtocolIdentifier
        get() = ExchangeProtocolIdentifier.OpenId4VpV1Multisigned
}

@Serializable
@SerialName(SerialNames.OPENID4VP_V1_UNSIGNED)
data class OpenId4VpResponseUnsigned(
    @SerialName(SerialNames.DATA)
    override val data: AuthenticationResponseParameters,
    @SerialName(SerialNames.ORIGIN)
    override val origin: String? = null,
) : DigitalCredentialInterface(), OpenId4VpResponse {
    override val protocol: ExchangeProtocolIdentifier
        get() = ExchangeProtocolIdentifier.OpenId4VpV1Unsigned
}

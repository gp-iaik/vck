package at.asitplus.dcapi.request.verifier

import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactStringSerializer
import at.asitplus.signum.indispensable.josef.JwsGeneral
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

@Serializable
@JsonClassDiscriminator(DigitalCredentialGetRequest.SerialNames.PROTOCOL)
sealed class DigitalCredentialGetRequest {
    abstract val protocol: ExchangeProtocolIdentifier

    @SerialName(SerialNames.DATA)
    abstract val data: Any

    @Serializable
    @SerialName(SerialNames.ORG_ISO_MDOC)
    data class IsoMdoc(
        @SerialName(SerialNames.DATA)
        override val data: IsoMdocRequest,
    ) : DigitalCredentialGetRequest() {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.IsoMdocAnnexC
    }

    sealed interface OpenId4Vp {
        @Serializable
        data class SignedDataElement(
            @SerialName(SerialNames.REQUEST)
            @Serializable(with = JwsCompactStringSerializer::class)
            val request: JwsCompact
        )

        @Serializable
        data class MultiSignedDataElement(
            @SerialName(SerialNames.REQUEST)
            val request: JwsGeneral
        )
    }

    @Serializable
    @SerialName(SerialNames.OPENID4VP_V1_SIGNED)
    data class OpenId4VpSigned(
        @SerialName(SerialNames.DATA)
        override val data: OpenId4Vp.SignedDataElement,
    ) : DigitalCredentialGetRequest(), OpenId4Vp {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OpenId4VpV1Signed
    }

    @Serializable
    @SerialName(SerialNames.OPENID4VP_V1_MULTISIGNED)
    data class OpenId4VpMultiSigned(
        @SerialName(SerialNames.DATA)
        override val data: OpenId4Vp.MultiSignedDataElement,
    ) : DigitalCredentialGetRequest(), OpenId4Vp {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OpenId4VpV1Signed
    }

    @Serializable
    @SerialName(SerialNames.OPENID4VP_V1_UNSIGNED)
    data class OpenId4VpUnsigned(
        @SerialName(SerialNames.DATA)
        override val data: AuthenticationRequestParameters,
    ) : DigitalCredentialGetRequest(), OpenId4Vp {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OpenId4VpV1Unsigned
    }

    object SerialNames {
        const val DATA = "data"
        const val REQUEST = "request"
        const val PROTOCOL = "protocol"
        const val ORG_ISO_MDOC = ExchangeProtocolIdentifier.ORG_ISO_MDOC
        const val OPENID4VP_V1_UNSIGNED = ExchangeProtocolIdentifier.OPENID4VP_V1_UNSIGNED
        const val OPENID4VP_V1_SIGNED = ExchangeProtocolIdentifier.OPENID4VP_V1_SIGNED
        const val OPENID4VP_V1_MULTISIGNED = ExchangeProtocolIdentifier.OPENID4VP_V1_MULTISIGNED
    }
}

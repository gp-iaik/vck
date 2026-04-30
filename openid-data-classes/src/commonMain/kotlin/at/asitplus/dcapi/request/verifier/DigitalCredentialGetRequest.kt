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
@JsonClassDiscriminator("protocol")
sealed class DigitalCredentialGetRequest {
    abstract val protocol: ExchangeProtocolIdentifier

    @Serializable
    @SerialName("org-iso-mdoc")
    data class IsoMdoc(
        @SerialName("data")
        val data: IsoMdocRequest,
    ) : DigitalCredentialGetRequest() {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.ISO_MDOC_ANNEX_C
    }

    sealed interface OpenId4Vp {
        @Serializable
        data class SignedDataElement(
            @SerialName("request")
            @Serializable(with = JwsCompactStringSerializer::class)
            val request: JwsCompact
        )

        @Serializable
        data class MultiSignedDataElement(
            @SerialName("request")
            val request: JwsGeneral
        )
    }

    @Serializable
    @SerialName("openid4vp-v1-signed")
    data class OpenId4VpSigned(
        @SerialName("data")
        val data: OpenId4Vp.SignedDataElement,
    ) : DigitalCredentialGetRequest(), OpenId4Vp {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OPENID4VP_V1_SIGNED
    }

    @Serializable
    @SerialName("openid4vp-v1-multisigned")
    data class OpenId4VpMultiSigned(
        @SerialName("data")
        val data: OpenId4Vp.MultiSignedDataElement,
    ) : DigitalCredentialGetRequest(), OpenId4Vp {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OPENID4VP_V1_SIGNED
    }

    @Serializable
    @SerialName("openid4vp-v1-unsigned")
    data class OpenId4VpUnsigned(
        @SerialName("data")
        val data: AuthenticationRequestParameters,
    ) : DigitalCredentialGetRequest(), OpenId4Vp {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OPENID4VP_V1_UNSIGNED
    }

}

package at.asitplus.dcapi.request

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsGeneralTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

/**
 * Abstract base class for requests received by the wallet via the Digital Credentials API.
 */
@Serializable
@JsonClassDiscriminator("protocol")
sealed interface DCAPIWalletRequest {
    val protocol: ExchangeProtocolIdentifier

    /** The credential IDs of the credentials the user has chosen in the UI provided by the system.
    Not available on iOS. */
    val credentialIds: Collection<String>?

    /** The package name of the calling (browser) application providing the calling origin. Not available on iOS. */
    val callingPackageName: String?
    val callingOrigin: String

    @Serializable
    data class IsoMdoc(
        @SerialName("isoMdocRequest")
        val isoMdocRequest: IsoMdocRequest,
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>? = null,
        @SerialName("callingPackageName")
        override val callingPackageName: String? = null,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : DCAPIWalletRequest {

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.ISO_MDOC_ANNEX_C
    }

    sealed class OpenId4Vp : DCAPIWalletRequest {
        abstract val request: String
        abstract override val protocol: ExchangeProtocolIdentifier
    }

    @ConsistentCopyVisibility
    @Serializable
    data class OpenId4VpMultiSigned private constructor(
        @SerialName("request")
        override val request: String,
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : OpenId4Vp() {

        constructor(
            request: JwsGeneralTyped<AuthenticationRequestParameters>,
            credentialIds: List<String>,
            callingPackageName: String,
            callingOrigin: String,
        ) : this(
            request = joseCompliantSerializer.encodeToString(request),
            credentialIds = credentialIds,
            callingPackageName = callingPackageName,
            callingOrigin = callingOrigin
        )

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OPENID4VP_V1_MULTISIGNED
    }

    @ConsistentCopyVisibility
    @Serializable
    data class OpenId4VpSigned private constructor(
        @SerialName("request")
        override val request: String,
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : DCAPIWalletRequest, OpenId4Vp() {

        constructor(
            request: JwsCompactTyped<AuthenticationRequestParameters>,
            credentialIds: List<String>,
            callingPackageName: String,
            callingOrigin: String,
        ) : this(
            request = request.jws.toString(),
            credentialIds = credentialIds,
            callingPackageName = callingPackageName,
            callingOrigin = callingOrigin
        )

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OPENID4VP_V1_SIGNED
    }


    @ConsistentCopyVisibility
    @Serializable
    data class OpenId4VpUnsigned private constructor(
        @SerialName("request")
        override val request: String,
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : DCAPIWalletRequest, OpenId4Vp() {

        constructor(
            request: AuthenticationRequestParameters,
            credentialIds: List<String>,
            callingPackageName: String,
            callingOrigin: String,
        ) : this(
            request = joseCompliantSerializer.encodeToString(request),
            credentialIds = credentialIds,
            callingPackageName = callingPackageName,
            callingOrigin = callingOrigin
        )

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OPENID4VP_V1_UNSIGNED

    }

}

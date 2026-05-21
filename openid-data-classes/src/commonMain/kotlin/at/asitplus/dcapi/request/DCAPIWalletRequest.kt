package at.asitplus.dcapi.request

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.JWS
import at.asitplus.signum.indispensable.josef.JwsCompactStringSerializer
import at.asitplus.signum.indispensable.josef.JwsTyped
import at.asitplus.signum.indispensable.josef.typed
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator
import kotlin.jvm.JvmInline
import at.asitplus.signum.indispensable.josef.JwsCompact as JosefJwsCompact
import at.asitplus.signum.indispensable.josef.JwsGeneral as JosefJwsGeneral

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
            get() = ExchangeProtocolIdentifier.IsoMdocAnnexC
    }

    sealed class OpenId4Vp : DCAPIWalletRequest {
        abstract val request: OpenId4VpRequest
        abstract override val protocol: ExchangeProtocolIdentifier


        sealed interface OpenId4VpRequest {
            @JvmInline
            @Serializable(with = JwsCompact.Serializer::class)
            value class JwsCompact(
                val request: JwsTyped<JosefJwsCompact, AuthenticationRequestParameters>
            ) : OpenId4VpRequest {
                object Serializer : KSerializer<JwsCompact> by TransformingSerializerTemplate(
                    parent = JwsTypedSerializerTemplate(
                        JwsCompactStringSerializer,
                        AuthenticationRequestParameters.serializer()
                    ),
                    encodeAs = JwsCompact::request,
                    decodeAs = ::JwsCompact,
                )
            }

            @JvmInline
            @Serializable(with = JwsGeneral.Serializer::class)
            value class JwsGeneral(
                val request: JwsTyped<JosefJwsGeneral, AuthenticationRequestParameters>
            ) : OpenId4VpRequest {
                object Serializer : KSerializer<JwsGeneral> by TransformingSerializerTemplate(
                    parent = JwsTypedSerializerTemplate(
                        JosefJwsGeneral.serializer(),
                        AuthenticationRequestParameters.serializer()
                    ),
                    encodeAs = JwsGeneral::request,
                    decodeAs = ::JwsGeneral,
                )
            }

            @JvmInline
            @Serializable
            value class Json(
                val request: AuthenticationRequestParameters,
            ) : OpenId4VpRequest
        }
    }

    @Serializable
    data class OpenId4VpMultiSigned(
        @SerialName("request")
        override val request: OpenId4VpRequest.JwsGeneral,
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : OpenId4Vp() {

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OpenId4VpV1Multisigned
    }

    @Serializable
    data class OpenId4VpSigned(
        @SerialName("request")
        override val request: OpenId4VpRequest.JwsCompact,
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : DCAPIWalletRequest, OpenId4Vp() {

        @Deprecated(
            "Changed request type from RequestParameter to JwsCompactTyped<AuthenticationRequestParameters>. Wrapping with `JarRequestParameters` is no longer necessary",
            replaceWith = ReplaceWith(
                "OpenId4VpSigned(request = (request as JarRequestParameters).request, credentialIds = credentialIds, callingPackageName = callingPackageName, callingOrigin = callingOrigin)"
            )
        )
        constructor(
            request: RequestParameters,
            credentialIds: Collection<String>,
            callingPackageName: String,
            callingOrigin: String,
        ) : this(
            request = OpenId4VpRequest.JwsCompact(JosefJwsCompact((request as JarRequestParameters).request!!).typed<AuthenticationRequestParameters, JosefJwsCompact>()),
            credentialIds = credentialIds,
            callingPackageName = callingPackageName,
            callingOrigin = callingOrigin
        )

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OpenId4VpV1Signed
    }

    @Serializable
    data class OpenId4VpUnsigned(
        @SerialName("request")
        override val request: OpenId4VpRequest.Json,
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : DCAPIWalletRequest, OpenId4Vp() {

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OpenId4VpV1Unsigned

    }

}

@Deprecated("Will move into Signum in the next release", level = DeprecationLevel.WARNING)
class JwsTypedSerializerTemplate<J : JWS, P>(
    jwsSerializer: KSerializer<J>,
    private val payloadSerializer: KSerializer<P>,
) : TransformingSerializerTemplate<JwsTyped<J, P>, J>(
    parent = jwsSerializer,
    encodeAs = { it.jws },
    decodeAs = { jws -> JwsTyped(jws, jws.getPayload(payloadSerializer).getOrThrow()) }
)
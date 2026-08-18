package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.extensions.getEncryptionTargetKey
import at.asitplus.wallet.lib.jws.DecryptJweFun
import at.asitplus.wallet.lib.jws.DecryptJweWithEphemeralKey
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.json
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.json.JsonObject

class RequestParser(
    /**
     * Need to implement if resources are defined by reference, i.e. the URL for a
     * [at.asitplus.signum.indispensable.josef.JsonWebKeySet],
     * or the request itself as `request_uri`, or `presentation_definition_uri`.
     * Implementations need to fetch the url passed in, and return either the body, if there is one,
     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
    @Deprecated("No longer used, decision moved to `AuthorizationRequestValidator`")
    private val requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { _: Any -> true },
    /**
     * Holds the ephemeral encryption keys advertised in `wallet_metadata` when fetching a request object with
     * `request_uri_method=post`, see [OpenId4VpHolder]. Leave `null` to reject encrypted request objects.
     */
    private val ephemeralEncryptionKeyService: EphemeralEncryptionKeyService? = null,
    /** Decrypts request objects sent by the verifier, keyed by the `kid` of the JWE. */
    private val decryptRequestObject: DecryptJweFun? =
        ephemeralEncryptionKeyService?.let { DecryptJweWithEphemeralKey(it) },
    /**
     * Callback to load [RequestObjectParameters] when loading a request object by reference (e.g. from `request_uri`)
     */
    private val buildRequestObjectParameters: suspend () -> RequestObjectParameters? = { null },
) {
    /**
     * Pass in the request by a relying party, that is either a complete URL,
     * or the POST body (e.g. the form-serialized values of the authorization request),
     * or a serialized JWS (which may have been extracted from a `request` parameter),
     * to parse the [AuthenticationRequestParameters], wrapped in [RequestParametersFrom].
     */
    suspend fun parseRequestParameters(
        input: String,
    ): KmmResult<RequestParametersFrom<*>> = catching {
        input.parseParameters().extractRequest()
    }

    private suspend fun String.parseParameters(): RequestParametersFrom<out RequestParameters> =
        parseAsJwsRequest(null)
            ?: parseFromParameters()
            ?: parseFromJson(null)
            ?: throw InvalidRequest("parse error: $this")

    private suspend fun RequestParametersFrom<out RequestParameters>.extractRequest(): RequestParametersFrom<*> =
        (this.parameters as? JarRequestParameters)?.let { extractRequest(it, this) } ?: this

    private fun String.parseFromParameters(): RequestParametersFrom<*>? = catchingUnwrapped {
        Url(this).let {
            RequestParametersFrom.Uri(
                url = it,
                parameters = json.decodeFromJsonElement(
                    RequestParameters.serializer(),
                    it.parameters.flattenEntries().toMap().decodeFromUrlQuery<JsonObject>()
                )
            )
        }
    }.getOrNull()

    private fun String.parseFromJson(
        parent: RequestParametersFrom<out RequestParameters>?,
    ): RequestParametersFrom<*>? = catchingUnwrapped {
        val params = joseCompliantSerializer.decodeFromString(RequestParameters.serializer(), this)
        RequestParametersFrom.Json(this, params, (parent as? RequestParametersFrom.Uri)?.url)
    }.getOrNull()

    suspend fun extractRequest(
        parameters: JarRequestParameters,
        parent: RequestParametersFrom<out RequestParameters>?,
    ): RequestParametersFrom<*>? = parameters.request?.let {
        it.parseAsJwsRequest(parent)
            ?: it.parseFromJson(parent)
    } ?: parameters.requestUri?.let { uri ->
        val method = parameters.requestUriMethod?.toHttpMethod() ?: HttpMethod.Get
        // only the POST request to the request URI endpoint has a channel for these, see OpenID4VP 1.0, 5.10, and it
        // is built once per request, since it carries the key the verifier shall encrypt this very request to
        val requestObjectParameters = if (method == HttpMethod.Post) buildRequestObjectParameters.invoke() else null
        remoteResourceRetriever.invoke(parameters.resourceRetrieverInput(uri, method, requestObjectParameters))?.let {
            (it.parseAsJweRequest(parent, requestObjectParameters.expectedEncryptionKeyId())
                ?: it.parseAsJwsRequest(parent)
                ?: it.parseFromJson(parent)
                ?: throw InvalidRequest("request_uri content not a valid request object: $uri"))
                .also { request -> request.requireWalletNonce(requestObjectParameters?.walletNonce) }
        }
    }

    /** The `kid` of the encryption key we have advertised in `wallet_metadata` for this very request. */
    private fun RequestObjectParameters?.expectedEncryptionKeyId(): String? =
        this?.walletMetadata?.jsonWebKeySet?.keys?.getEncryptionTargetKey()?.keyId

    /**
     * Per [OpenID4VP 1.0, 5.10.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-request-uri-response):
     * If we passed a `wallet_nonce` when fetching the request object, it MUST come back in the request object,
     * otherwise we MUST terminate request processing.
     */
    private fun RequestParametersFrom<*>.requireWalletNonce(sent: String?) {
        if (sent == null) return
        val received = (parameters as? AuthenticationRequestParameters)?.walletNonce
        if (received != sent)
            throw InvalidRequest("wallet_nonce we sent is missing from the request object, got: $received")
    }

    private fun JarRequestParameters.resourceRetrieverInput(
        uri: String,
        method: HttpMethod,
        requestObjectParameters: RequestObjectParameters?,
    ): RemoteResourceRetrieverInput = RemoteResourceRetrieverInput(
        url = uri,
        method = method,
        headers = mapOf(HttpHeaders.Accept to MediaTypes.Application.AUTHZ_REQ_JWT),
        requestObjectParameters = requestObjectParameters
    )

    private suspend fun String.parseAsJwsRequest(
        parent: RequestParametersFrom<out RequestParameters>?,
    ): RequestParametersFrom<*>? =
        catching { JwsCompactTyped<RequestParameters>(this) }
            .getOrNull()?.let { jws ->
                RequestParametersFrom.Jws(
                    jws = jws.jws,
                    parameters = jws.payload,
                    parent = (parent as? RequestParametersFrom.Uri)?.url
                )
            }

    /**
     * Decrypts a request object encrypted to the key we have advertised in `wallet_metadata`, as per
     * [OpenID4VP 1.0, 5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-request-uri-method-post),
     * and parses the plaintext, which is a signed or plain request object.
     *
     * Returns `null` if this is not a JWE at all, and throws if it is one that we can't or shouldn't decrypt.
     */
    private suspend fun String.parseAsJweRequest(
        parent: RequestParametersFrom<out RequestParameters>?,
        expectedKeyId: String?,
    ): RequestParametersFrom<*>? {
        if (count { it == '.' } != 4) return null
        val jwe = JweEncrypted.deserialize(this).getOrNull() ?: return null
        if (expectedKeyId == null)
            throw InvalidRequest("Verifier sent an encrypted request, but we did not request encryption")
        if (jwe.header.keyId != expectedKeyId)
            throw InvalidRequest("Encrypted request key does not match the key we advertised")
        if (decryptRequestObject == null)
            throw InvalidRequest("Verifier sent an encrypted request, we can't decrypt it")
        val decrypted = decryptRequestObject.invoke(jwe).getOrElse {
            throw InvalidRequest("Decryption of request object failed", it)
        }
        return decrypted.payload.parseAsJwsRequest(parent)
            ?: decrypted.payload.parseFromJson(parent)
            ?: throw InvalidRequest("Decrypted request object is not a valid request object")
    }

}

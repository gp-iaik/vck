package at.asitplus.dcapi.request.verifier

import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import at.asitplus.dcapi.request.toRequestParametersFrom
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.typed

fun String.decodeDigitalCredentialRequestOptions(): DigitalCredentialRequestOptions =
    joseCompliantSerializer.decodeFromString(this)

fun DigitalCredentialRequestOptions.toRequestParametersFrom(
    selectedProtocol: String,
    credentialIds: Collection<String>,
    callingOrigin: String,
    callingPackageName: String? = null,
): RequestParametersFrom.DcApiRequest =
    toRequestParametersFrom(
        selectedProtocol = ExchangeProtocolIdentifier(selectedProtocol),
        credentialIds = credentialIds,
        callingOrigin = callingOrigin,
        callingPackageName = callingPackageName,
    )

fun DigitalCredentialRequestOptions.toRequestParametersFrom(
    selectedProtocol: ExchangeProtocolIdentifier,
    credentialIds: Collection<String>,
    callingOrigin: String,
    callingPackageName: String? = null,
): RequestParametersFrom.DcApiRequest {
    val request = requests.find { it.protocol == selectedProtocol }
        ?: throw IllegalStateException("Unable to find suitable DC API request. Protocol may not be supported.")

    return when (request) {
        is DigitalCredentialGetRequest.OpenId4VpSigned ->
            RequestParametersFrom.OpenId4VpDcApiSigned(
                jwsTyped = request.data.request.typed(),
                credentialIds = credentialIds,
                callingPackageName = requireNotNull(callingPackageName) {
                    "callingPackageName is required for OpenID4VP DC API requests"
                },
                callingOrigin = callingOrigin,
            )

        is DigitalCredentialGetRequest.OpenId4VpMultiSigned ->
            RequestParametersFrom.OpenId4VpDcApiMultiSigned(
                jwsTyped = request.data.request.typed(),
                credentialIds = credentialIds,
                callingPackageName = requireNotNull(callingPackageName) {
                    "callingPackageName is required for OpenID4VP DC API requests"
                },
                callingOrigin = callingOrigin,
            )

        is DigitalCredentialGetRequest.OpenId4VpUnsigned ->
            RequestParametersFrom.OpenId4VpDcApiUnsigned(
                parameters = request.data,
                jsonString = joseCompliantSerializer.encodeToString(request.data),
                credentialIds = credentialIds,
                callingPackageName = requireNotNull(callingPackageName) {
                    "callingPackageName is required for OpenID4VP DC API requests"
                },
                callingOrigin = callingOrigin,
            )

        is DigitalCredentialGetRequest.IsoMdoc ->
            request.data.toRequestParametersFrom(
                credentialIds = credentialIds,
                callingPackageName = callingPackageName,
                callingOrigin = callingOrigin,
            )
    }
}

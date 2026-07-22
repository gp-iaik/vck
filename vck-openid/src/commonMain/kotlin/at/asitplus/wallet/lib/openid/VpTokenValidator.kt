package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.ClaimFormat
import at.asitplus.dif.PresentationSubmissionDescriptor
import at.asitplus.iso.DeviceResponse
import at.asitplus.jsonpath.JsonPath
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.ResponseParametersFrom
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryResponse
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.MdocDeviceSignatureVerifier
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.coroutines.cancellation.CancellationException

/**
 * Validates the `vp_token` of an OpenID4VP authentication response, independently of the transport
 * that delivered it: URL/QR (see [OpenId4VpVerifier]) or the W3C Digital Credentials API (see [DcApiVerifier]).
 * The only transport-specific step, calculation of the ISO session transcript, is delegated to
 * the injected [SessionTranscriptCalculator].
 */
internal class VpTokenValidator(
    /** Verifies the presentations in the response; the verifiers pass their [at.asitplus.wallet.lib.agent.NonceChallengeVerifier]. */
    private val nonceAwareVerifier: Verifier,
    /** Verifies the mdoc device signature against the session transcript. */
    private val mdocDeviceSignatureVerifier: MdocDeviceSignatureVerifier,
    /** Calculates the ISO session transcript for the transport the response was received over. */
    private val createSessionTranscript: SessionTranscriptCalculator,
) {

    /**
     * Extract and verifies verifiable presentations, according to format defined in
     * [OpenID for VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html),
     * as referenced by [OpenID for VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
     *
     * [origin] is the calling origin from the W3C Digital Credentials API, or `null` for URL/QR transport.
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun validateVpToken(
        authnRequest: AuthenticationRequestParameters,
        responseParameters: ResponseParametersFrom,
        origin: String?,
    ): KmmResult<VpTokenValidationResult> = catching {
        val expectedNonce = authnRequest.nonce
            ?: throw IllegalArgumentException("nonce not present in $authnRequest")
        val vpToken = responseParameters.parameters.vpToken
            ?: throw IllegalArgumentException("vp_token not present in ${responseParameters.parameters}")
        val clientIdRequired = responseParameters.clientIdRequired

        authnRequest.presentationDefinition?.let {
            val presentationSubmission = responseParameters.parameters.presentationSubmission?.descriptorMap
                ?: throw IllegalArgumentException("Presentation Exchange need to present a presentation submission.")

            val presentation = presentationSubmission.associate { descriptor ->
                descriptor.id to verifyPresentationResult(
                    claimFormat = descriptor.format,
                    relatedPresentation = descriptor.relatedPresentation(vpToken),
                    expectedNonce = expectedNonce,
                    input = responseParameters,
                    clientId = authnRequest.clientId,
                    responseUrl = authnRequest.responseUrl ?: authnRequest.redirectUrlExtracted,
                    transactionData = authnRequest.transactionData,
                    clientIdRequired = clientIdRequired,
                    origin = origin,
                )
            }

            VpTokenValidationResultPresentationExchange(
                inputDescriptorResponseValidations = presentation,
            )
        } ?: authnRequest.dcqlQuery?.let { query ->
            val presentation = vpToken.jsonObject.mapKeys {
                DCQLCredentialQueryIdentifier(it.key)
            }.mapValues { (credentialQueryId, relatedPresentation) ->
                val credentialQuery = query.credentialQuery(credentialQueryId)
                    ?: throw IllegalArgumentException("Unknown credential query identifier.")

                relatedPresentation.jsonArray.map {
                    verifyPresentationResult(
                        claimFormat = credentialQuery.format.toClaimFormat(),
                        relatedPresentation = it.jsonPrimitive,
                        expectedNonce = expectedNonce,
                        input = responseParameters,
                        clientId = authnRequest.clientId,
                        responseUrl = authnRequest.responseUrl ?: authnRequest.redirectUrlExtracted,
                        transactionData = authnRequest.transactionData,
                        clientIdRequired = clientIdRequired,
                        origin = origin,
                        requireCryptographicHolderBinding = query.credentialQuery(credentialQueryId)?.requireCryptographicHolderBinding,
                    )
                }
            }
            val validationResult = DCQLQueryAdapter(query).validateSubmissionRequirements(presentation)
            VpTokenValidationResultDCQL(
                credentialQueryResponseValidations = presentation,
                submissionRequirementsValidationResult = validationResult,
            )
        } ?: throw IllegalArgumentException("Unsupported presentation mechanism")
    }

    private fun DCQLQueryAdapter.validateSubmissionRequirements(
        presentation: Map<DCQLCredentialQueryIdentifier, List<KmmResult<VerifyPresentationResult>>>
    ): KmmResult<Unit> = catching {
        val queryResponse = DCQLQueryResponse(presentation.mapValues { entry ->
            entry.value.map { result -> result.getOrThrow() }
        })
        checkSubmissionRequirements(queryResponse).getOrThrow()
    }

    private fun DCQLQuery.credentialQuery(id: DCQLCredentialQueryIdentifier) =
        credentials.associateBy { it.id }[id]

    private fun PresentationSubmissionDescriptor.relatedPresentation(vpToken: JsonElement) =
        JsonPath(cumulativeJsonPath).query(vpToken).first().value

    private fun CredentialFormatEnum.toClaimFormat(): ClaimFormat = when (this) {
        CredentialFormatEnum.JWT_VC -> ClaimFormat.JWT_VP
        CredentialFormatEnum.DC_SD_JWT -> ClaimFormat.SD_JWT
        CredentialFormatEnum.MSO_MDOC -> ClaimFormat.MSO_MDOC
        CredentialFormatEnum.NONE,
        CredentialFormatEnum.JWT_VC_JSON_LD,
        CredentialFormatEnum.JSON_LD,
            -> throw IllegalStateException("Unsupported credential format")
    }

    private suspend fun verifyPresentationResult(
        claimFormat: ClaimFormat,
        relatedPresentation: JsonElement,
        expectedNonce: String,
        input: ResponseParametersFrom,
        clientId: String?,
        responseUrl: String?,
        transactionData: List<TransactionDataBase64Url>?,
        clientIdRequired: Boolean,
        origin: String?,
        requireCryptographicHolderBinding: Boolean? = null,
    ): KmmResult<VerifyPresentationResult> = catching {
        when (claimFormat) {
            ClaimFormat.SD_JWT -> {
                val sdJwt = SdJwtSigned.parseCatching(relatedPresentation.extractContent()).getOrElse {
                    throw IllegalArgumentException("relatedPresentation")
                }
                nonceAwareVerifier.verifyPresentationSdJwt(
                    input = sdJwt,
                    challenge = expectedNonce,
                    transactionData = transactionData,
                    requireCryptographicHolderBinding = requireCryptographicHolderBinding != false,
                    // OpenID4VP over DC API binds the KB-JWT to the calling Origin instead of the Client Identifier.
                    // For URL/QR transport, no override is supplied and the verifier's Client Identifier is used.
                    audience = origin?.let { "origin:$it" },
                )
            }

            ClaimFormat.JWT_VP -> if (requireCryptographicHolderBinding != false) {
                nonceAwareVerifier.verifyPresentationVcJwt(
                    input = JwsCompactTyped<VerifiablePresentationJws>(
                        relatedPresentation.extractContent()
                    ),
                    challenge = expectedNonce
                )
            } else {
                nonceAwareVerifier.verifyUnsignedVcJws(
                    input = relatedPresentation.extractContent()
                ).map {
                    VerifyPresentationResult.SuccessUnsigned(it.vc)
                }
            }

            ClaimFormat.MSO_MDOC -> nonceAwareVerifier.verifyPresentationIsoMdoc(
                input = relatedPresentation.extractContent().decodeToByteArray(Base64UrlStrict)
                    .let { coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(it) },
                verifyDocument = mdocDeviceSignatureVerifier.verifyDocument(
                    sessionTranscript = createSessionTranscript(
                        input = input,
                        clientId = clientId,
                        expectedNonce = expectedNonce,
                        hasBeenEncrypted = input.hasBeenEncrypted,
                        responseUrl = responseUrl,
                        clientIdRequired = clientIdRequired,
                        origin = origin
                    )
                )
            )

            else -> throw IllegalArgumentException("descriptor.format: $claimFormat")
        }.getOrThrow()
    }

    // To be reconsidered when supporting [DCQLCredentialQueryInstance.multiple]
    private fun JsonElement.extractContent(): String = when (this) {
        is JsonArray -> first().extractContent()
        is JsonObject -> toString()
        is JsonPrimitive -> content
        JsonNull -> throw IllegalArgumentException("Can't extract string from JsonNull")
    }
}

private val PresentationSubmissionDescriptor.cumulativeJsonPath: String
    get() {
        var cummulativeJsonPath = this.path
        var descriptorIterator = this.nestedPath
        while (descriptorIterator != null) {
            cummulativeJsonPath += descriptorIterator.path.substring(1)
            descriptorIterator = descriptorIterator.nestedPath
        }
        return cummulativeJsonPath
    }

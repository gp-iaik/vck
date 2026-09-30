package at.asitplus.wallet.lib.agent.validation.relyingParty

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.iso.SessionTranscript
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsTyped
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate.WrpCwtRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate.WrpJwtRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest.WrpDcqlCredentialQuery
import io.github.aakira.napier.Napier
import kotlinx.serialization.decodeFromByteArray

/**
 * Parses an authentication request and wraps necessary data for WRP validation.
 */
object WrpAuthenticationRequestValidator {

    operator fun invoke(
        request: RequestParametersFrom<*>
    ): KmmResult<WrpRequestData> = catching {
        when (request) {
            is RequestParametersFrom.Jws<*> -> {
                val request = request.jwsTyped as? JwsTyped<JwsCompact, AuthenticationRequestParameters>
                    ?: throw IllegalArgumentException("Unable to cast request as JwsTyped<JwsCompact, AuthenticationRequestParameters>")
                val clientId = requireNotNull(request.payload.clientId) { "No client_id in request" }
                val jwsTyped = request.payload.verifierInfo.singleRegistrationCertificate()
                val registrationCertificate = WrpJwtRegistrationCertificate(jwsTyped = jwsTyped)
                val dcqlQuery = requireNotNull(request.payload.dcqlQuery) { "No DCQL query in request" }
                val wrpCredentialRequest = dcqlQuery.credentials.map { WrpDcqlCredentialQuery(it) }
                val accessCertificate = WrpAccessCertificate(request.jws.jwsHeader.certificateChain)

                WrpRequestData(
                    clientId = clientId,
                    accessCertificate = accessCertificate,
                    registrationCertificate = mapOf(registrationCertificate to wrpCredentialRequest),
                )
            }

            is RequestParametersFrom.OpenId4VpDcApiSigned -> {
                val dcqlQuery = requireNotNull(request.parameters.dcqlQuery) { "No DCQL query in request" }
                requireNotNull(request.parameters.clientId) { "No client_id in request" }
                val jwsTyped = request.parameters.verifierInfo.singleRegistrationCertificate()
                val registrationCertificate = WrpJwtRegistrationCertificate(jwsTyped = jwsTyped)
                val wrpCredentialRequest = dcqlQuery.credentials.map { WrpDcqlCredentialQuery(it) }
                val accessCertificate = WrpAccessCertificate(request.jwsTyped.jws.jwsHeader.certificateChain)

                WrpRequestData(
                    clientId = request.parameters.clientId,
                    accessCertificate = accessCertificate,
                    registrationCertificate = mapOf(registrationCertificate to wrpCredentialRequest)
                )
            }

            is RequestParametersFrom.IsoMdocDcApi -> throw WrpValidationException.UnsupportedRequest(
                "Session transcript is required for ISO mdoc reader authentication"
            )

            else -> throw WrpValidationException.UnsupportedRequest("Request not supported for validation: $request")
        }
    }

    suspend operator fun invoke(
        request: RequestParametersFrom.IsoMdocDcApi,
        sessionTranscript: SessionTranscript
    ): KmmResult<WrpRequestData> = catching {
        val deviceRequest = request.parameters.isoMdocRequest.deviceRequest
        val accessCertificateChain = ReaderAuthenticationVerifier()(deviceRequest, sessionTranscript).getOrThrow()
        val registrationCertificate: Map<WrpRegistrationCertificate, List<WrpCredentialRequest>> =
            deviceRequest.docRequests.map { docRequest ->
                val euWrprcBytes = docRequest.itemsRequest.value.requestInfo?.euWrprc
                    ?: throw WrpValidationException.RegistrationCertificateMissing(
                        "Registration certificate missing in DocRequest $docRequest"
                    )
                val (euWrprc, payload) = catchingUnwrapped {
                    coseCompliantSerializer.decodeFromByteArray<CoseSigned<ByteArray>>(euWrprcBytes)
                        .let { it to parseCose(euWrprc = it) }
                }.getOrElse {
                    throw WrpValidationException.RegistrationCertificateMalformed(
                        "Registration certificate in DocRequest could not be parsed: ${it.message}", it
                    )
                }
                val registrationCertificate = WrpCwtRegistrationCertificate(cose = euWrprc, payload = payload)
                Pair(registrationCertificate, listOf(WrpCredentialRequest.WrpDocRequest(docRequest)))
            }.groupBy({ it.first }, { it.second })
                .mapValues { (_, requests) -> requests.flatten() }

        WrpRequestData(
            accessCertificate = WrpAccessCertificate(accessCertificateChain),
            registrationCertificate = registrationCertificate
        )
    }

    /**
     * The single registration certificate in [this] `verifier_info`, failing with a [WrpValidationException] that
     * tells a missing one apart from one that cannot be parsed, keeping the reason.
     */
    private fun List<VerifierInfo>?.singleRegistrationCertificate(): JwsCompactTyped<WrpPayload> {
        if (this == null) throw WrpValidationException.RegistrationCertificateMissing("No verifier_info in request")
        val registrationCertificates = filter { it.format.equals(REGISTRATION_CERT_FORMAT, ignoreCase = true) }
        val registrationCertificate = when (registrationCertificates.size) {
            0 -> throw WrpValidationException.RegistrationCertificateMissing(
                "No $REGISTRATION_CERT_FORMAT in verifier_info of request"
            )

            1 -> registrationCertificates.single()
            else -> throw WrpValidationException.RegistrationCertificateMalformed(
                "Request must contain exactly one WRPRC"
            )
        }
        return catchingUnwrapped { JwsCompactTyped<WrpPayload>(registrationCertificate.data) }.getOrElse {
            throw WrpValidationException.RegistrationCertificateMalformed(
                "Registration certificate could not be parsed: ${it.message}", it
            )
        }
    }

    fun VerifierInfo.parseJws() = catchingUnwrapped {
        require(format.equals(REGISTRATION_CERT_FORMAT, ignoreCase = true))
        JwsCompactTyped<WrpPayload>(data)
    }.onFailure { Napier.w("Failed to parse JWS data for $this (${REGISTRATION_CERT_FORMAT}).", it) }
        .getOrNull()

    fun parseCose(euWrprc: CoseSigned<ByteArray>): WrpPayload {
        val type = euWrprc.protectedHeader.type ?: throw IllegalArgumentException("Missing typ header in euWrprc.")
        if (type != "rc-wrp+cwt") {
            throw IllegalArgumentException("Invalid typ header in euWrprc: expected 'rc-wrp+cwt', got '$type'.")
        }

        val payloadBytes = euWrprc.payload ?: throw IllegalStateException("euWrprc payload not found.")
        return coseCompliantSerializer.decodeFromByteArray<WrpPayload>(bytes = payloadBytes)
    }
}

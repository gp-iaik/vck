package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dcapi.DCAPIResponse
import at.asitplus.dcapi.DigitalCredentialInterface
import at.asitplus.dcapi.IsoMdocResponse
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest

class DcApiHolder(
    private val openId4VpHolder: OpenId4VpHolder,
    private val iso180137AnnexCHolder: Iso180137AnnexCHolder,
) {

    suspend fun prepare(
        request: RequestParametersFrom.DcApiRequest,
    ): KmmResult<DcApiPreparationState> = catching {
        when (request) {
            is RequestParametersFrom.OpenId4VpDcApiSigned ->
                DcApiPreparationState.OpenId4Vp(
                    openId4VpHolder.startAuthorizationResponsePreparation(request).getOrThrow()
                )

            is RequestParametersFrom.OpenId4VpDcApiMultiSigned ->
                DcApiPreparationState.OpenId4Vp(
                    openId4VpHolder.startAuthorizationResponsePreparation(request).getOrThrow()
                )

            is RequestParametersFrom.OpenId4VpDcApiUnsigned ->
                DcApiPreparationState.OpenId4Vp(
                    openId4VpHolder.startAuthorizationResponsePreparation(request).getOrThrow()
                )

            is RequestParametersFrom.IsoMdocDcApi ->
                DcApiPreparationState.Iso180137AnnexC(
                    request = request,
                    presentationRequest = iso180137AnnexCHolder.createPresentationRequest(request).getOrThrow(),
                )
        }
    }

    suspend fun getMatchingCredentials(
        state: DcApiPreparationState,
    ): KmmResult<CredentialMatchingResult<SubjectCredentialStore.StoreEntry>> =
        when (state) {
            is DcApiPreparationState.OpenId4Vp ->
                openId4VpHolder.getMatchingCredentials(state.state)

            is DcApiPreparationState.Iso180137AnnexC ->
                iso180137AnnexCHolder.getMatchingCredentials(state.request)
        }

    suspend fun finalize(
        state: DcApiPreparationState,
        credentialPresentation: CredentialPresentation? = null,
    ): KmmResult<DigitalCredentialInterface> = catching {
        when (state) {
            is DcApiPreparationState.OpenId4Vp -> {
                val result = openId4VpHolder.finalizeAuthorizationResponse(
                    preparationState = state.state,
                    credentialPresentation = credentialPresentation,
                ).getOrThrow()
                val dcApiResult = result as? AuthenticationResponseResult.DcApi
                    ?: throw IllegalStateException("Expected OpenID4VP DC API response")
                dcApiResult.params as? DigitalCredentialInterface
                    ?: throw IllegalStateException("OpenID4VP DC API response is not a DigitalCredentialInterface")
            }

            is DcApiPreparationState.Iso180137AnnexC -> {
                val presentation = credentialPresentation as? CredentialPresentation.PresentationExchangePresentation
                    ?: throw IllegalArgumentException("ISO 18013-7 Annex C requires a Presentation Exchange presentation")
                IsoMdocResponse(
                    DCAPIResponse(
                        iso180137AnnexCHolder.finalizeResponse(
                            request = state.request,
                            credentialPresentation = presentation,
                        ).getOrThrow()
                    )
                )
            }
        }
    }
}

sealed class DcApiPreparationState {
    abstract val request: RequestParametersFrom.DcApiRequest
    abstract val presentationRequest: CredentialPresentationRequest?

    data class OpenId4Vp(
        val state: AuthorizationResponsePreparationState,
    ) : DcApiPreparationState() {
        override val request: RequestParametersFrom.DcApiRequest
            get() = state.request as RequestParametersFrom.DcApiRequest
        override val presentationRequest: CredentialPresentationRequest?
            get() = state.credentialPresentationRequest
    }

    data class Iso180137AnnexC(
        override val request: RequestParametersFrom.IsoMdocDcApi,
        override val presentationRequest: CredentialPresentationRequest.PresentationExchangeRequest,
    ) : DcApiPreparationState()
}

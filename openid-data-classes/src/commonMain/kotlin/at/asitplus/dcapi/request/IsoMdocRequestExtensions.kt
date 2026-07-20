package at.asitplus.dcapi.request

import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer

/**
 * Wraps an ISO/IEC 18013-7 Annex C request with the platform metadata required by [RequestParametersFrom.DcApiRequest].
 *
 * The caller must obtain [callingOrigin] from its trusted platform API. [credentialIds] and [callingPackageName] are
 * optional platform matcher metadata; ISO/IEC 18013-7 Annex C does not require a calling package name.
 */
fun IsoMdocRequest.toRequestParametersFrom(
    callingOrigin: String,
    credentialIds: Collection<String>? = null,
    callingPackageName: String? = null,
): RequestParametersFrom.IsoMdocDcApi =
    RequestParametersFrom.IsoMdocDcApi(
        parameters = RequestParametersFrom.IsoMdocDcApi.IsoMdocRequestWrapper(this),
        jsonString = joseCompliantSerializer.encodeToString(this),
        credentialIds = credentialIds,
        callingPackageName = callingPackageName,
        callingOrigin = callingOrigin,
    )

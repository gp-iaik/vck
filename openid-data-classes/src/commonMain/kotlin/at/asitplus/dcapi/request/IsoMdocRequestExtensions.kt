package at.asitplus.dcapi.request

import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer

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

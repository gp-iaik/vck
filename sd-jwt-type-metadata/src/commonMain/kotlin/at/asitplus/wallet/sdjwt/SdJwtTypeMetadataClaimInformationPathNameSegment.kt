package at.asitplus.wallet.sdjwt

import kotlin.jvm.JvmInline

@JvmInline
value class SdJwtTypeMetadataClaimInformationPathNameSegment(
    val string: String
) : SdJwtTypeMetadataClaimInformationPathSegment {

    override fun toString() = "\"$string\""
}
package at.asitplus.dcapi.request

import at.asitplus.catchingUnwrapped
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ExchangeProtocolIdentifier(
    val protocol: String
) {
    val openIdVersion
        get() = catchingUnwrapped {
            if (!isIsoMdocRequest) protocol.removePrefix(PART_OPENID4VP).split(DELIMITER)[1] else null
        }.getOrNull()

    val openId4VpRequestType
        get() = catchingUnwrapped {
            if (!isIsoMdocRequest) protocol.removePrefix(PART_OPENID4VP).split(DELIMITER)[2] else null
        }.getOrNull()

    val isSignedOpenId4VpRequest: Boolean
        get() = openId4VpRequestType?.let { it == PART_SIGNED || it == PART_MULTISIGNED } == true

    val isUnsignedOpenId4VpRequest: Boolean
        get() = openId4VpRequestType?.let { it == PART_UNSIGNED } == true

    val isIsoMdocRequest: Boolean
        get() = protocol == ORG_ISO_MDOC

    private fun checkOpenId4VpProtocolIdentifier() {
        val openId4vpFinal = protocol.startsWith(PART_OPENID4VP) && protocol.count { it == DELIMITER } == 2
        require(openId4vpFinal || protocol == PART_OPENID4VP /* draft 24*/)
        require(openIdVersion == PART_V1 || openIdVersion == null /* draft 24*/) {
            "Only version 1 is supported, got $openIdVersion"
        }
        openId4VpRequestType?.let {
            require(it == PART_UNSIGNED || it == PART_SIGNED || it == PART_MULTISIGNED) {
                "Request type must be one of: unsigned, signed or multisigned"
            }
        }
    }

    init {
        if (!isIsoMdocRequest) {
            checkOpenId4VpProtocolIdentifier()
        }
    }

    companion object {
        private const val DELIMITER = '-'

        /** `openid4vp` */
        private const val PART_OPENID4VP = "openid4vp"

        /** `v1` */
        private const val PART_V1 = "v1"

        /** `multisigned` */
        private const val PART_MULTISIGNED = "multisigned"

        /** `signed` */
        private const val PART_SIGNED = "signed"

        /** `unsigned` */
        private const val PART_UNSIGNED = "unsigned"

        const val ORG_ISO_MDOC = "org-iso-mdoc"

        /** `openid4vp-v1-unsigned` */
        const val OPENID4VP_V1_UNSIGNED = "$PART_OPENID4VP$DELIMITER$PART_V1$DELIMITER$PART_UNSIGNED"

        /** `openid4vp-v1-signed` */
        const val OPENID4VP_V1_SIGNED = "$PART_OPENID4VP$DELIMITER$PART_V1$DELIMITER$PART_SIGNED"

        /** `openid4vp-v1-multisigned` */
        const val OPENID4VP_V1_MULTISIGNED = "$PART_OPENID4VP$DELIMITER$PART_V1$DELIMITER$PART_MULTISIGNED"

        val OpenId4VpV1Unsigned = ExchangeProtocolIdentifier(OPENID4VP_V1_UNSIGNED)

        val OpenId4VpV1Signed = ExchangeProtocolIdentifier(OPENID4VP_V1_SIGNED)

        val OpenId4VpV1Multisigned = ExchangeProtocolIdentifier(OPENID4VP_V1_MULTISIGNED)

        /** `org-iso-mdoc` */
        val IsoMdocAnnexC = ExchangeProtocolIdentifier(ORG_ISO_MDOC)
    }
}
package at.asitplus.wallet.sdjwt

import kotlin.jvm.JvmInline

@JvmInline
value class DelegatingSdJwtTypeMetadataDocumentRetriever(
    private val delegates: Collection<SdJwtTypeMetadataDocumentRetriever>
): Collection<SdJwtTypeMetadataDocumentRetriever> by delegates, SdJwtTypeMetadataDocumentRetriever {
    override suspend fun retrieve(
        sdJwtVcType: SdJwtVcType,
        integrityMetadata: W3cSubresourceIntegrityMetadata?
    ) = delegates.firstNotNullOfOrNull {
        it.retrieve(
            sdJwtVcType = sdJwtVcType,
            integrityMetadata = integrityMetadata,
        )
    }
}
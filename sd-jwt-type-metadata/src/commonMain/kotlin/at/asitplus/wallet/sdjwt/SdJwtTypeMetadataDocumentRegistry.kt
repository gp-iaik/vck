package at.asitplus.wallet.sdjwt

import kotlin.jvm.JvmInline


@JvmInline
value class SdJwtTypeMetadataDocumentRegistry(
    private val delegate: Map<SdJwtVcType, SdJwtTypeMetadataDocument>
) : Map<SdJwtVcType, SdJwtTypeMetadataDocument> by delegate, SdJwtTypeMetadataDocumentRetriever {
    constructor(vararg elements: Pair<SdJwtVcType, SdJwtTypeMetadataDocument>) : this(elements.toMap())

    override suspend fun retrieve(
        sdJwtVcType: SdJwtVcType,
        isStatic: Boolean
    ) = delegate[sdJwtVcType]
}

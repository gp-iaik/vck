package at.asitplus.wallet.sdjwt

fun interface SdJwtTypeMetadataDocumentRetriever {
    /**
     * This resolver performs integrity checks and merges the inheritance tree
     */
    suspend fun retrieve(
        sdJwtVcType: SdJwtVcType,
    ): SdJwtTypeMetadataDocument
}
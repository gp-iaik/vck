package at.asitplus.wallet.sdjwt

fun interface SdJwtTypeMetadataDocumentRetriever {
    suspend fun retrieve(
        sdJwtVcType: SdJwtVcType,
        /**
         * A Consumer MAY cache Type Metadata for a SD-JWT VC type. If a hash for integrity protection is present in the
         * Type Metadata as defined in Section 5, the Consumer MAY assume that the Type Metadata is static and can be
         * cached indefinitely. Otherwise
         */
        integrityMetadata: W3cSubresourceIntegrityMetadata?,
    ): SdJwtTypeMetadataDocument?
}
package at.asitplus.wallet.sdjwt

fun interface SdJwtTypeMetadataDocumentIntegrityChecker {
    companion object {
        val DEFAULT = SignumSdJwtTypeMetadataDocumentIntegrityChecker
    }

    suspend fun checkIntegrity(
        document: SdJwtTypeMetadataDocument,
        integrityHash: W3cSubresourceIntegrityMetadata,
    )
}



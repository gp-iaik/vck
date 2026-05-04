package at.asitplus.wallet.sdjwt

data class DelegatingSdJwtTypeMetadataDocumentIntegrityChecker(
    val subresourceIntegrityChecker: W3cSubresourceIntegrityChecker
): SdJwtTypeMetadataDocumentIntegrityChecker {
    @Throws
    override suspend fun checkIntegrity(
        document: SdJwtTypeMetadataDocument,
        integrityHash: W3cSubresourceIntegrityMetadata,
    ) = subresourceIntegrityChecker.checkIntegrity(
        data = document.original.toString().encodeToByteArray(),
        integrityHash = integrityHash,
    )
}
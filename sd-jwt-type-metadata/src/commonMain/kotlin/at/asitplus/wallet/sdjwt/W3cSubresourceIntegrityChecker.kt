package at.asitplus.wallet.sdjwt

fun interface W3cSubresourceIntegrityChecker {
    @Throws
    suspend fun checkIntegrity(
        data: ByteArray,
        integrityHash: W3cSubresourceIntegrityMetadata,
    )
}
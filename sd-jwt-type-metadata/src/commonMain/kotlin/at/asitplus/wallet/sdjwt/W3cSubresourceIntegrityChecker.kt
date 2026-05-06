package at.asitplus.wallet.sdjwt

fun interface W3cSubresourceIntegrityChecker {
    suspend fun checkIntegrity(
        data: ByteArray,
        integrityHash: W3cSubresourceIntegrityMetadata,
    )
}
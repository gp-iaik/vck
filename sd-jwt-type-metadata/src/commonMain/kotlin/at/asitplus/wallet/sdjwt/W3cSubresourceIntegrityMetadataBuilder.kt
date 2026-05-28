package at.asitplus.wallet.sdjwt

import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHashAlgorithm

interface W3cSubresourceIntegrityMetadataBuilder : W3cSubresourceIntegrityChecker {
    suspend fun build(
        data: ByteArray,
        /**
         * algorithm = null for using some implementation default
         */
        algorithm: ContentSecurityPolicySourceExpressionHashAlgorithm? = null,
    ): W3cSubresourceIntegrityMetadata

    override suspend fun checkIntegrity(
        data: ByteArray,
        integrityHash: W3cSubresourceIntegrityMetadata
    ) {
        val digest = build(
            data,
            algorithm = integrityHash.algorithm,
        ).byteArray
        check(digest.contentEquals(integrityHash.byteArray)) {
            "Expected integrity hash to be ${integrityHash.byteArray.toHexString()}, but got ${digest.toHexString()}."
        }
    }
}
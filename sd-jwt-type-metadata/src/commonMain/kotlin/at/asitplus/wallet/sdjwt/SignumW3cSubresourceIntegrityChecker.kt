package at.asitplus.wallet.sdjwt

import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHashAlgorithm
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.supreme.hash.digest

object SignumW3cSubresourceIntegrityChecker : W3cSubresourceIntegrityChecker {
    override suspend fun checkIntegrity(
        data: ByteArray,
        integrityHash: W3cSubresourceIntegrityMetadata
    ) {
        val digest = when(integrityHash.algorithm) {
            ContentSecurityPolicySourceExpressionHashAlgorithm.sha256 -> Digest.SHA256
            ContentSecurityPolicySourceExpressionHashAlgorithm.sha384 -> Digest.SHA384
            ContentSecurityPolicySourceExpressionHashAlgorithm.sha512 -> Digest.SHA512
        }.digest(data)
        check(
            digest.contentEquals(
                integrityHash.byteArray
            )
        ) {
            "Expected integrity hash to be ${integrityHash.byteArray.toHexString()}, but got ${digest.toHexString()}."
        }
    }
}
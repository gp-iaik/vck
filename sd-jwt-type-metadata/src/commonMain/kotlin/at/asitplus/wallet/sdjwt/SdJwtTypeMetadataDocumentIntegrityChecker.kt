package at.asitplus.wallet.sdjwt

import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHashAlgorithm
import at.asitplus.signum.supreme.hash.digest

fun interface SdJwtTypeMetadataDocumentIntegrityChecker {
    @Throws
    suspend fun checkIntegrity(
        document: SdJwtTypeMetadataDocument,
        integrityHash: SdJwtTypeMetadataIntegrityHash,
    )
}

object SignumSdJwtTypeMetadataDocumentIntegrityChecker : SdJwtTypeMetadataDocumentIntegrityChecker {
    override suspend fun checkIntegrity(
        document: SdJwtTypeMetadataDocument,
        integrityHash: SdJwtTypeMetadataIntegrityHash
    ) {
        val digest = when(integrityHash.algorithm) {
            ContentSecurityPolicySourceExpressionHashAlgorithm.sha256 -> at.asitplus.signum.indispensable.Digest.SHA256
            ContentSecurityPolicySourceExpressionHashAlgorithm.sha384 -> at.asitplus.signum.indispensable.Digest.SHA384
            ContentSecurityPolicySourceExpressionHashAlgorithm.sha512 -> at.asitplus.signum.indispensable.Digest.SHA512
        }.digest(document.original.toString().encodeToByteArray())
        check(
            digest.contentEquals(
                integrityHash.byteArray
            )
        ) {
            "Expected integrity hash to be ${integrityHash.byteArray.toHexString()}, but got ${digest.toHexString()}."
        }
    }
}
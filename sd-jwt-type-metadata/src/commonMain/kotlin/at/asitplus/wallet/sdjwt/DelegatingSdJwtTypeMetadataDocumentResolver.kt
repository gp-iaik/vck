package at.asitplus.wallet.sdjwt

data class DelegatingSdJwtTypeMetadataDocumentResolver(
    val documentRetriever: SdJwtTypeMetadataDocumentRetriever,
    val integrityChecker: SdJwtTypeMetadataDocumentIntegrityChecker = SdJwtTypeMetadataDocumentIntegrityChecker.DEFAULT,
): SdJwtTypeMetadataDocumentResolver {
    override suspend fun resolve(
        sdJwtVcType: SdJwtVcType,
        integrityHash: W3cSubresourceIntegrityMetadata?,
    ): SdJwtTypeMetadata {
        val visited = mutableListOf<SdJwtVcType>()
        val ancestry = mutableListOf<SdJwtTypeMetadataDocument>()
        var nextSdJwtVcType: SdJwtVcType? = sdJwtVcType
        var nextIntegrityHash = integrityHash
        while(nextSdJwtVcType != null) {
            check(nextSdJwtVcType !in visited) {
                "Expected inheritance to be non-cyclic, but was cyclic after ${visited.size} nodes, extending $nextSdJwtVcType from ${visited.last()} in $visited."
            }
            val document = documentRetriever.retrieve(
                nextSdJwtVcType,
                nextIntegrityHash
            ) ?: throw IllegalStateException(
                "Failed to resolve sd jwt type document for: $sdJwtVcType"
            )
            check(document.definition.vct == nextSdJwtVcType) {
                """Expected the extending type to specify the vct of the extended type in `extends`, but got `${nextSdJwtVcType}` instead of `${document.definition.vct}`."""
            }
            nextIntegrityHash?.let {
                integrityChecker.checkIntegrity(
                    document,
                    it,
                )
            }

            ancestry.add(document)

            nextSdJwtVcType = document.definition.extends
            nextIntegrityHash = document.definition.extendsIntegrity
            visited.add(document.definition.vct)
        }

        // we already did all the checks, now we just need to merge them
        return ancestry.dropLast(1).foldRight(
            ancestry.last().definition.toSdJwtTypeMetadata()
        ) { document, acc ->
            document.definition.extend(acc)
        }
    }
}
package at.asitplus.wallet.sdjwt

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class SdJwtTypeMetadataClaimInformationDisplayMetadataList(
    @Serializable(with = Serializer::class)
    private val list: UnorderedMultiSet<SdJwtTypeMetadataClaimInformationDisplayMetadata>
) : Iterable<SdJwtTypeMetadataClaimInformationDisplayMetadata> by list {
    constructor(
        vararg elements: SdJwtTypeMetadataClaimInformationDisplayMetadata
    ): this(UnorderedMultiSet(elements.asList()))
    constructor(list: List<SdJwtTypeMetadataClaimInformationDisplayMetadata>) : this(UnorderedMultiSet(list))

    class Serializer :
        KSerializer<UnorderedMultiSet<SdJwtTypeMetadataClaimInformationDisplayMetadata>> by UnorderedMultiSet.ListSerializer(
            SdJwtTypeMetadataClaimInformationDisplayMetadata.serializer()
        )
}
package at.asitplus.wallet.sdjwt

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class SdJwtTypeMetadataTypeDisplayInformationList(
    @Serializable(with = Serializer::class)
    private val collection: UnorderedMultiSet<SdJwtTypeMetadataTypeDisplayInformation>
) : Iterable<SdJwtTypeMetadataTypeDisplayInformation> by collection {
    constructor(
        vararg elements: SdJwtTypeMetadataTypeDisplayInformation
    ): this(UnorderedMultiSet(elements.asList()))
    constructor(list: List<SdJwtTypeMetadataTypeDisplayInformation>) : this(UnorderedMultiSet(list))

    class Serializer :
        KSerializer<UnorderedMultiSet<SdJwtTypeMetadataTypeDisplayInformation>> by UnorderedMultiSet.ListSerializer(
            SdJwtTypeMetadataTypeDisplayInformation.serializer()
        )
}
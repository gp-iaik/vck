package at.asitplus.wallet.sdjwt

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class SdJwtTypeMetadataClaimInformationList(
    @Serializable(with = Serializer::class)
    private val collection: UnorderedMultiSet<SdJwtTypeMetadataClaimInformation>
) : Iterable<SdJwtTypeMetadataClaimInformation> by collection {
    constructor(
        vararg elements: SdJwtTypeMetadataClaimInformation
    ): this(UnorderedMultiSet(elements.asList()))
    constructor(list: List<SdJwtTypeMetadataClaimInformation>) : this(UnorderedMultiSet(list))

    class Serializer :
        KSerializer<UnorderedMultiSet<SdJwtTypeMetadataClaimInformation>> by UnorderedMultiSet.ListSerializer(
            SdJwtTypeMetadataClaimInformation.serializer()
        )
}


package at.asitplus.wallet.lib.openid

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQuery
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLJwtVcCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLJwtVcCredentialQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.toIsoMdocClaimPath
import com.benasher44.uuid.uuid4

/**
 * This is a helper class to build a [CredentialPresentationRequest] from a collection of [RequestOptionsCredential]
 * to be used in [OpenId4VpRequestOptions].
 */
data class CredentialPresentationRequestBuilder(
    /** Requested credentials, should be at least one. */
    val credentials: Collection<RequestOptionsCredential>,
) {
    fun toPresentationExchangeRequest() = CredentialPresentationRequest.PresentationExchangeRequest(
        PresentationDefinition(
            id = uuid4().toString(),
            inputDescriptors = credentials.map {
                it.toInputDescriptor()
            }
        )
    )

    private fun RequestOptionsCredential.toInputDescriptor(): InputDescriptor = DifInputDescriptor(
        id = buildId(),
        format = toFormatHolder(),
        constraints = toConstraint(),
    )

    private fun RequestOptionsCredential.toFormatHolder() = when (this.representation) {
        ConstantIndex.CredentialRepresentation.PLAIN_JWT -> FormatHolder(
            jwtVp = FormatContainerJwt()
        )

        ConstantIndex.CredentialRepresentation.SD_JWT -> FormatHolder(
            sdJwt = FormatContainerSdJwt()
        )

        ConstantIndex.CredentialRepresentation.ISO_MDOC -> FormatHolder(
            msoMdoc = FormatContainerJwt()
        )
    }

    fun toDCQLRequest(): CredentialPresentationRequest.DCQLRequest? {
        return CredentialPresentationRequest.DCQLRequest(
            DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    credentials.mapNotNull {
                        it.toQuery()
                    }.takeIf {
                        it.isNotEmpty()
                    }?.toNonEmptyList() ?: return null
                ),
            )
        )
    }

    fun toIso180137AnnexCDeviceRequest() = credentials.map {
        if (it.representation != CredentialRepresentation.ISO_MDOC) {
            throw UnsupportedOperationException("Wrong representation: Only ISO MDoc is supported")
        }
        val docType = it.credentialScheme.isoDocType ?: throw IllegalStateException("Missing doc type")
        val itemsRequestList = it.effectiveRequestedAttributePaths().map { reqAttr ->
            val (namespace, claimName) = reqAttr.toIsoMdocClaimPath(it.credentialScheme).toIsoMdocNamespaceAndClaimName()
            namespace to SingleItemsRequest(claimName, false)
        }.groupBy(
            keySelector = { (namespace, _) -> namespace },
            valueTransform = { (_, itemRequest) -> itemRequest }
        ).mapValues { (_, itemRequests) ->
            ItemsRequestList(itemRequests)
        }
        DocRequest(ByteStringWrapper(ItemsRequest(docType, itemsRequestList)))
    }.toTypedArray().let {
        DeviceRequest("1.0", it)
    }

    private fun RequestOptionsCredential.toQuery(): DCQLCredentialQuery? = when (representation) {
        CredentialRepresentation.PLAIN_JWT -> toJwtVcQuery()
        CredentialRepresentation.SD_JWT -> toSdJwtQuery()
        CredentialRepresentation.ISO_MDOC -> toIsoMdocQuery()
    }

    private fun RequestOptionsCredential.toJwtVcQuery() = credentialScheme.vcType?.let { vcType ->
        DCQLJwtVcCredentialQuery(
            id = DCQLCredentialQueryIdentifier(id),
            meta = DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = nonEmptyListOf(
                    listOfNotNull(vcType)
                )
            ),
            claims = nonOptionalAndOptionalRequestedAttributes()
                .takeIf { it.isNotEmpty() } // requesting all claims if none are specified
                ?.map { (attributePath, _) ->
                    DCQLJsonClaimsQuery(path = attributePath)
                }?.toNonEmptyList()
                ?.let { DCQLClaimsQueryList(it) }
        )
    }

    private fun RequestOptionsCredential.toSdJwtQuery() = credentialScheme.sdJwtType?.let { sdJwtType ->
        DCQLSdJwtCredentialQuery(
            id = DCQLCredentialQueryIdentifier(id),
            meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf(sdJwtType)
            ),
            claims = nonOptionalAndOptionalRequestedAttributes()
                .takeIf { it.isNotEmpty() } // requesting all claims if none are specified
                ?.map { (attributePath, _) ->
                    DCQLJsonClaimsQuery(path = attributePath)
                }?.toNonEmptyList()
                ?.let { DCQLClaimsQueryList(it) }
        )
    }

    private fun RequestOptionsCredential.toIsoMdocQuery() = credentialScheme.isoDocType?.let { isoDocType ->
        DCQLIsoMdocCredentialQuery(
            id = DCQLCredentialQueryIdentifier(id),
            meta = DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                doctypeValue = isoDocType
            ),
            claims = nonOptionalAndOptionalRequestedAttributes()
                .takeIf { it.isNotEmpty() } // requesting all claims if none are specified
                ?.map { (attributePath, _) ->
                    DCQLIsoMdocClaimsQuery(
                        path = attributePath.toIsoMdocClaimPath(credentialScheme)
                    )
                }?.toNonEmptyList()
                ?.let { DCQLClaimsQueryList(it) }
        )
    }

    // TODO: how to properly handle non-required claims?
    private fun RequestOptionsCredential.nonOptionalAndOptionalRequestedAttributes(): List<Pair<DCQLClaimsPathPointer, Boolean>> =
        effectiveRequestedAttributePaths().map { it to true } +
                effectiveRequestedOptionalAttributePaths().map { it to false }

    private fun DCQLClaimsPathPointer.toIsoMdocNamespaceAndClaimName(): Pair<String, String> {
        require(segments.size == 2 && segments.all { it is NameSegment }) {
            "ISO mdoc requested attribute paths must contain namespace and claim name segments"
        }
        return (segments[0] as NameSegment).name to (segments[1] as NameSegment).name
    }
}

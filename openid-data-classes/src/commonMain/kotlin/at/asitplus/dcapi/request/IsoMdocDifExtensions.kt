package at.asitplus.dcapi.request

import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatHolder
import at.asitplus.iso.DocRequest
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.NameSegment

fun IsoMdocRequest.toDifInputDescriptors(): List<DifInputDescriptor> =
    deviceRequest.docRequests.toDifInputDescriptors()

fun Array<DocRequest>.toDifInputDescriptors(): List<DifInputDescriptor> =
    map { it.toDifInputDescriptor() }

fun DocRequest.toDifInputDescriptor(): DifInputDescriptor {
    val itemsRequest = itemsRequest.value
    return DifInputDescriptor(
        id = itemsRequest.docType,
        format = FormatHolder(msoMdoc = FormatContainerJwt()),
        constraints = Constraint(
            fields = itemsRequest.namespaces.flatMap { (namespace, items) ->
                items.entries.map { item ->
                    ConstraintField(
                        path = listOf(
                            NormalizedJsonPath(
                                NameSegment(namespace),
                                NameSegment(item.dataElementIdentifier),
                            ).toString()
                        ),
                        intentToRetain = item.intentToRetain
                    )
                }
            }.toSet()
        )
    )
}

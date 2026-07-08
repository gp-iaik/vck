package at.asitplus.dcapi.request

import at.asitplus.dcapi.request.verifier.testIsoMdocRequest
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.NameSegment
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

val IsoMdocDifExtensionsTest by matrixSuite {

    test("converts ISO mdoc request to DIF input descriptors") {
        val descriptors = testIsoMdocRequest.data.toDifInputDescriptors()

        descriptors shouldHaveSize 1
        val descriptor = descriptors.single()
        descriptor.id shouldBe "org.iso.18013.5.1.mDL"
        descriptor.format?.msoMdoc.shouldNotBeNull()
        val fields = descriptor.constraints?.fields.orEmpty()
        fields shouldHaveSize 11
        val familyNamePath = NormalizedJsonPath(
            NameSegment("org.iso.18013.5.1"),
            NameSegment("family_name"),
        ).toString()
        fields.associate { it.path.single() to it.intentToRetain }[familyNamePath] shouldBe false
    }
}

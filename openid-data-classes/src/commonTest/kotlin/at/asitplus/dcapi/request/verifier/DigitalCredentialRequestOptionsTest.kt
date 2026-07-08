package at.asitplus.dcapi.request.verifier

import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

val DigitalCredentialRequestOptionsTest by matrixSuite {

    test("decode signed openid4vp request options") {
        val requestJwt = Json.parseToJsonElement(DIGITAL_CREDENTIAL_REQUEST_OPTIONS_JSON)
            .jsonObject["requests"].shouldNotBeNull()
            .jsonArray[0]
            .jsonObject["data"].shouldNotBeNull()
            .jsonObject["request"].shouldNotBeNull()
            .jsonPrimitive
            .content

        val decoded = joseCompliantSerializer
            .decodeFromString<DigitalCredentialRequestOptions>(DIGITAL_CREDENTIAL_REQUEST_OPTIONS_JSON)
        decoded.requests.size shouldBe 2
        val request = decoded.requests.first()
            .shouldBeInstanceOf<DigitalCredentialGetRequest.OpenId4VpSigned>()
        request.data.request.toString() shouldBe requestJwt
    }

    test("convert OpenID4VP selected request to wallet request parameters") {
        val decoded = DigitalCredentialRequestOptions(listOf(testUnsignedOpenId4VpRequest))

        val request = decoded.toRequestParametersFrom(
            selectedProtocol = ExchangeProtocolIdentifier.OPENID4VP_V1_UNSIGNED,
            credentialIds = listOf("credential-id"),
            callingPackageName = "example.package",
            callingOrigin = "https://verifier.example",
        )

        val unsigned = request.shouldBeInstanceOf<RequestParametersFrom.OpenId4VpDcApiUnsigned>()
        unsigned.credentialIds shouldBe listOf("credential-id")
        unsigned.callingPackageName shouldBe "example.package"
        unsigned.callingOrigin shouldBe "https://verifier.example"
    }

    test("convert ISO mdoc selected request to wallet request parameters") {
        val request = testDigitalCredentialRequestOptions.toRequestParametersFrom(
            selectedProtocol = ExchangeProtocolIdentifier.ORG_ISO_MDOC,
            credentialIds = listOf("document-id"),
            callingPackageName = "example.package",
            callingOrigin = "https://verifier.example",
        )

        val isoMdoc = request.shouldBeInstanceOf<RequestParametersFrom.IsoMdocDcApi>()
        isoMdoc.credentialIds shouldBe listOf("document-id")
        isoMdoc.callingPackageName shouldBe "example.package"
        isoMdoc.callingOrigin shouldBe "https://verifier.example"
    }
}

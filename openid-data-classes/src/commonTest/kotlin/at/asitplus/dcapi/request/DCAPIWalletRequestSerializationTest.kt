package at.asitplus.dcapi.request

import at.asitplus.dcapi.request.verifier.testIsoMdocRequest
import at.asitplus.dcapi.request.verifier.testSignedOpenId4VpRequest
import at.asitplus.dcapi.request.verifier.testUnsignedOpenId4VpRequest
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsFlattened
import at.asitplus.signum.indispensable.josef.JwsGeneralTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJwsFlattened
import at.asitplus.signum.indispensable.josef.toJwsGeneral
import at.asitplus.signum.indispensable.josef.typed
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain

val DCAPIWalletRequestSerializationTest by testSuite {
    test("openid4vp unsigned request round-trips") {
        val request = DCAPIWalletRequest.OpenId4VpUnsigned(
            request = testUnsignedOpenId4VpRequest.data,
            credentialIds = listOf("044c78be429198ffc2a66d935ff86e4e2bdb8ca2ab0cd1bacc85f3a73d8347b4"),
            callingPackageName = "com.android.chrome",
            callingOrigin = "https://wallet.a-sit.at"
        )

        val encoded = joseCompliantSerializer.encodeToString<DCAPIWalletRequest>(request)
        encoded.shouldContain("\"credentialIds\"")
        encoded.shouldNotContain("\"credentialId\"")
        val decoded = joseCompliantSerializer.decodeFromString<DCAPIWalletRequest>(encoded)

        decoded shouldBe request
    }

    test("openid4vp signed request round-trips") {
        val request: JwsCompactTyped<AuthenticationRequestParameters> = testSignedOpenId4VpRequest.data.request.typed()
        val walletRequest = DCAPIWalletRequest.OpenId4VpSigned(
            request = request,
            credentialIds = listOf("044c78be429198ffc2a66d935ff86e4e2bdb8ca2ab0cd1bacc85f3a73d8347b4"),
            callingPackageName = "com.android.chrome",
            callingOrigin = "https://wallet.a-sit.at"
        )
        walletRequest.request.shouldNotContain("\"")

        val encoded = joseCompliantSerializer.encodeToString<DCAPIWalletRequest>(walletRequest)
        encoded.shouldContain("\"credentialIds\"")
        encoded.shouldNotContain("\"credentialId\"")
        val decoded = joseCompliantSerializer.decodeFromString<DCAPIWalletRequest>(encoded)

        decoded shouldBe walletRequest
    }

    test("openid4vp multisigned request round-trips") {
        val requestElement: JwsFlattened = testSignedOpenId4VpRequest.data.request.toJwsFlattened()
        val request: JwsGeneralTyped<AuthenticationRequestParameters> = (0..5).map { requestElement }.toJwsGeneral().typed()
        val walletRequest = DCAPIWalletRequest.OpenId4VpMultiSigned(
            request = request,
            credentialIds = listOf("044c78be429198ffc2a66d935ff86e4e2bdb8ca2ab0cd1bacc85f3a73d8347b4"),
            callingPackageName = "com.android.chrome",
            callingOrigin = "https://wallet.a-sit.at"
        )

        val encoded = joseCompliantSerializer.encodeToString<DCAPIWalletRequest>(walletRequest)
        encoded.shouldContain("\"credentialIds\"")
        encoded.shouldNotContain("\"credentialId\"")
        val decoded = joseCompliantSerializer.decodeFromString<DCAPIWalletRequest>(encoded)

        decoded shouldBe walletRequest
    }

    test("iso mdoc request round-trips") {
        val request = DCAPIWalletRequest.IsoMdoc(
            isoMdocRequest = testIsoMdocRequest.data,
            credentialIds = listOf("044c78be429198ffc2a66d935ff86e4e2bdb8ca2ab0cd1bacc85f3a73d8347b4"),
            callingOrigin = "https://wallet.a-sit.at"
        )

        val encoded = joseCompliantSerializer.encodeToString<DCAPIWalletRequest>(request)
        encoded.shouldContain("\"credentialIds\"")
        encoded.shouldNotContain("\"credentialId\"")
        val decoded = joseCompliantSerializer.decodeFromString<DCAPIWalletRequest>(encoded)

        decoded shouldBe request
    }
}

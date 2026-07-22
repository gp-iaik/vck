package at.asitplus.openid

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

val AuthenticationRequestOriginTest by matrixSuite {

    test("expected origin comparison uses exact strings") {
        val parameters = AuthenticationRequestParameters(
            expectedOrigins = listOf("https://example.com/"),
        )

        parameters.verifyExpectedOrigin("https://example.com/") shouldBe true
        parameters.verifyExpectedOrigin("https://example.com") shouldBe false
        parameters.verifyExpectedOrigin("https://EXAMPLE.com/") shouldBe false
    }
}

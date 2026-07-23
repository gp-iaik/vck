package at.asitplus.openid

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

val AuthenticationRequestOriginTest by matrixSuite {

    test("expected origin comparison uses exact strings") {
        val parameters = AuthenticationRequestParameters(
            expectedOrigins = listOf("https://xn--maraa-rta.example"),
        )

        parameters.verifyExpectedOrigin("https://xn--maraa-rta.example") shouldBe true
        parameters.verifyExpectedOrigin("https://xn--maraa-rta.example/") shouldBe false
        parameters.verifyExpectedOrigin("https://XN--MARAA-RTA.EXAMPLE") shouldBe false
    }
}

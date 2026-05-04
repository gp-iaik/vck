package at.asitplus.rfc3986uri

import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.shouldBe
import io.ktor.http.Url

@Suppress("unused")
val Rfc3986PercentEncodingAwareStringTest by testSuite {
    testSuite("case insensitivity") {
        withData(
            mapOf(
                "%C3%A4" to "ä",
                "%C3%B6" to "ö",
                "%C3%BC" to "ü",
                "%C3%9F" to "ß",
                "%C3%A9" to "é",
                "%E2%82%AC" to "€",
                "%C2%A3" to "£",
                "%C2%A5" to "¥",
            ).mapValues {
                it.key to it.value
            }
        ) {
            Rfc3986PercentEncodingAwareString(it.first).decode() shouldBe it.second
        }
    }
}

package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow

@Suppress("unused")
val SvgContentPlaceholderTest by testSuite {
    testSuite("valid placeholders are accepted") {
        withData(
            "name",
            "address_street_address",
            "claim_1",
            "addr2",
            "a1b2c3",
            "_private",
            "_0",
            "A",
            "camelCase42",
        ) {
            shouldNotThrowAny { SvgContentPlaceholder(it) }
        }
    }

    testSuite("invalid placeholders are rejected") {
        withData(
            "1claim",
            "0",
            "42abc",
        ) {
            shouldThrow<IllegalArgumentException> { SvgContentPlaceholder(it) }
        }
    }
}

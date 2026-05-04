package at.asitplus.wallet.sdjwt

import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

@Suppress("unused")
val SelectiveDisclosureConstraintsTest by testSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("values") {
        SelectiveDisclosureConstraints.always.name shouldBe "always"
        SelectiveDisclosureConstraints.allowed.name shouldBe "allowed"
        SelectiveDisclosureConstraints.never.name shouldBe "never"
    }
}




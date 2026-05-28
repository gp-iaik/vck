package at.asitplus.wallet.sdjwt

import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

@Suppress("unused")
val SvgTemplatePropertyColorSchemeTest by testSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("values") {
        SvgTemplatePropertyColorScheme.dark.name shouldBe "dark"
        SvgTemplatePropertyColorScheme.light.name shouldBe "light"
    }
}



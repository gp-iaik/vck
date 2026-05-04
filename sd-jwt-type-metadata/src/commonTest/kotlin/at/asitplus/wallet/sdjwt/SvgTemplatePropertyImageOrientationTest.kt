package at.asitplus.wallet.sdjwt

import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

@Suppress("unused")
val SvgTemplatePropertyImageOrientationTest by testSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("values") {
        SvgTemplatePropertyImageOrientation.landscape.name shouldBe "landscape"
        SvgTemplatePropertyImageOrientation.portrait.name shouldBe "portrait"
    }
}


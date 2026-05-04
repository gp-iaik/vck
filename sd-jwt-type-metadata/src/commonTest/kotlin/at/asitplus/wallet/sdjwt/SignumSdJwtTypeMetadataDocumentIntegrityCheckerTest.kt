package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny

@Suppress("unused")
val SignumW3cSubresourceIntegrityCheckerTest by testSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    testSuite("values") {
        withData(
            mapOf(
                "alert('Hello, world.');" to "sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
            ).mapValues {
                it.key.encodeToByteArray() to W3cSubresourceIntegrityMetadata(it.value)
            }
        ) {
            shouldNotThrowAny {
                SignumW3cSubresourceIntegrityChecker.checkIntegrity(
                    data = it.first,
                    integrityHash = it.second
                )
            }
        }
    }
}

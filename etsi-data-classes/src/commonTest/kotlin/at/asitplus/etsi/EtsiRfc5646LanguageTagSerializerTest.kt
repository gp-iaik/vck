package at.asitplus.etsi

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

val EtsiRfc5646LanguageTagSerializerTest by matrixSuite {
    test("deserialization normalizes language tags to lowercase") {
        Json.decodeFromString(
            EtsiRfc5646LanguageTagSerializer(),
            "\"EN-us\"",
        ).string shouldBe "en-us"
    }
}

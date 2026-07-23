package at.asitplus.iso

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

val OriginSerializerTest by matrixSuite {

    test("host is serialized in lowercase") {
        "https://MacBook-Air.local:8443".serializeOrigin() shouldBe
                "https://macbook-air.local:8443"
    }

    test("authority-based origin with another scheme is serialized") {
        "ftp://EXAMPLE.com:21/path".serializeOrigin() shouldBe "ftp://example.com"
    }

    test("opaque Android application origin is not serialized") {
        "android:apk-key-hash:AbCdEf".serializeOrigin() shouldBe null
    }
}

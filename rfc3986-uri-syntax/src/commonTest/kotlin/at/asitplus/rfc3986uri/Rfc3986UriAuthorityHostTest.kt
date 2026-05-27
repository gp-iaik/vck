package at.asitplus.rfc3986uri

import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

@Suppress("unused")
val Rfc3986AuthorityHostTest by testSuite {
    testSuite("case insensitivity") {
        withData(
            mapOf(
                "v6 simple" to Pair("aaAA", "aAaA"),
            )
        ) {
            Rfc3986AuthorityHost("[${it.first}]") shouldBe Rfc3986AuthorityHost("[${it.second}]")
        }
    }

    testSuite("parsing success") {
        withData(
            "www.ietf.org",
            "[aaAA::]",
            "127.0.0.1",
            "v1.a",
            "[v1.a]",
            "[vff.test:data]",
        ) {it ->
            shouldNotThrowAny {
                Rfc3986AuthorityHost(it)
            }
        }
    }

    testSuite("IPv4 octet zero") {
        test("single zero octet is valid") {
            shouldNotThrowAny { Rfc3986AuthorityHostIPv4("0.0.0.0") }
            shouldNotThrowAny { Rfc3986AuthorityHostIPv4("192.0.2.0") }
            shouldNotThrowAny { Rfc3986UniformResourceIdentifier("http://0.0.0.0/") }
            shouldNotThrowAny { Rfc3986UniformResourceIdentifier("http://192.0.2.128/") }
        }
        test("leading zero in multi-digit octet is rejected") {
            shouldThrow<IllegalArgumentException> { Rfc3986AuthorityHostIPv4("01.2.3.4") }
            shouldThrow<IllegalArgumentException> { Rfc3986AuthorityHostIPv4("192.00.2.1") }
        }
    }

    testSuite("IPvFuture round-trips through URI") {
        withData(
            "http://[v1.foo]/path",
            "http://[vff.test:data]/",
        ) { uri ->
            Rfc3986UniformResourceIdentifier(uri).string shouldBe uri
        }
    }
}


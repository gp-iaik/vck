package at.asitplus.wallet.sdjwt

import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHashAlgorithm
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

@Suppress("unused")
val W3cSubresourceIntegrityMetadataTest by testSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("values") {
        W3cSubresourceIntegrityMetadata(
            "sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
        ).expression.run {
            algorithm shouldBe ContentSecurityPolicySourceExpressionHashAlgorithm.sha384
            hashValue.toString() shouldBe "H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
        }
        W3cSubresourceIntegrityMetadata(
            "sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
        ).expression.run {
            algorithm shouldBe ContentSecurityPolicySourceExpressionHashAlgorithm.sha384
            hashValue.toString() shouldBe "H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
        }
    }

    testSuite("reserializing json elements preserves string character order") {
        // this is important for integrity checks since we're currently storing the original data as a json element
        withData(
            """{"vct":"https://betelgeuse.example.com/education_credential/v42","name":"Betelgeuse Education Credential - First Version","description":"This is our first version of the education credential. Don't panic.","display":[{"locale":"en-US","name":"Betelgeuse Education Credential","description":"An education credential for all carbon-based life forms on Betelgeuse.","rendering":{"simple":{"logo":{"uri":"https://betelgeuse.example.com/public/education-logo.png","uri#integrity":"sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=","alt_text":"Betelgeuse Ministry of Education logo"},"background_image":{"uri":"https://betelgeuse.example.com/public/credential-background.png","uri#integrity":"sha256-5sBT7mMLylHLWrrS/qQ8aHpRAxoraWVmWX6eUVMlrrA="},"background_color":"#12107c","text_color":"#FFFFFF"},"svg_templates":[{"uri":"https://betelgeuse.example.com/public/credential-english.svg","uri#integrity":"sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=","properties":{"orientation":"landscape","color_scheme":"light","contrast":"high"}}]}},{"locale":"de-DE","name":"Betelgeuse-Bildungsnachweis","description":"Ein Bildungsnachweis für alle kohlenstoffbasierten Lebensformen auf Betelgeuse.","rendering":{"simple":{"logo":{"uri":"https://betelgeuse.example.com/public/education-logo-de.png","uri#integrity":"sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=","alt_text":"Logo des Betelgeusischen Bildungsministeriums"},"background_image":{"uri":"https://betelgeuse.example.com/public/credential-background-de.png","uri#integrity":"sha256-9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1ULmXfg=="},"background_color":"#12107c","text_color":"#FFFFFF"},"svg_templates":[{"uri":"https://betelgeuse.example.com/public/credential-german.svg","uri#integrity":"sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=","properties":{"orientation":"landscape","color_scheme":"light","contrast":"high"}}]}}],"claims":[{"path":["name"],"display":[{"locale":"de-DE","label":"Vor- und Nachname","description":"Der Name des/der Studierenden"},{"locale":"en-US","label":"Name","description":"The name of the student"}],"sd":"always","mandatory":true},{"path":["address"],"display":[{"locale":"de-DE","label":"Adresse","description":"Adresse zum Zeitpunkt des Abschlusses"},{"locale":"en-US","label":"Address","description":"Address at the time of graduation"}],"sd":"always"},{"path":["address","street_address"],"display":[{"locale":"de-DE","label":"Straße"},{"locale":"en-US","label":"Street Address"}],"sd":"always","svg_id":"address_street_address"},{"path":["degrees"],"display":[{"locale":"de-DE","label":"Abschlüsse","description":"Abschlüsse des/der Studierenden"},{"locale":"en-US","label":"Degrees","description":"Degrees earned by the student"}],"sd":"never"},{"path":["degrees",null],"sd":"always"},{"path":["degrees",null,"field_of_study"],"display":[{"locale":"de-DE","label":"Studienfach"},{"locale":"en-US","label":"Field of Study"}],"sd":"never"},{"path":["degrees",null,"date_awarded"],"display":[{"locale":"de-DE","label":"Verleihungsdatum"},{"locale":"en-US","label":"Date Awarded"}],"sd":"always"}]}"""
        ) {
            Json.decodeFromString(
                SdJwtTypeMetadataDocument.serializer(),
                it,
            ).original.toString() shouldBe it
        }
    }
}

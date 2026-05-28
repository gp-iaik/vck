package at.asitplus.csp2

import at.asitplus.rfc3986uri.Rfc3986UriSchemeName
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ContentSecurityPolicySourceExpressionScheme(
    val uriSchemeName: Rfc3986UriSchemeName
) : ContentSecurityPolicySourceExpression {
    override fun toString() = uriSchemeName.string + ":"
}
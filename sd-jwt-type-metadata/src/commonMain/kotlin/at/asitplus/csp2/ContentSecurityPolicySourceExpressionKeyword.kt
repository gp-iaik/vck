package at.asitplus.csp2

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ContentSecurityPolicySourceExpressionKeyword(
    val content: ContentSecurityPolicySourceExpressionKeywordContent,
): ContentSecurityPolicySourceExpression {
    override fun toString() = "'${content.name}'"
}
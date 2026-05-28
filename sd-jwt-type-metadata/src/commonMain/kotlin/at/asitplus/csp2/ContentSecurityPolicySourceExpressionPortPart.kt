package at.asitplus.csp2

import kotlin.jvm.JvmInline

@JvmInline
value class ContentSecurityPolicySourceExpressionPortPart(
    val string: String
) {
    init {
        require(Regex(REGEX_GROUP).matches(string)) {
            "Expected string to be a well-formed source expression port part, but got `$string`"
        }
    }

    companion object {
        const val REGEX_GROUP = """(\*|[0-9]+)"""
        const val REGEX = """:$REGEX_GROUP"""
    }
}
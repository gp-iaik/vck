package at.asitplus.rfc3986uri

/**
 * We don't really want to go further down the rabbit hole.
 */
sealed interface Rfc3986AuthorityHost {
    companion object {
        operator fun invoke(string: String): Rfc3986AuthorityHost {
            return if(string.startsWith("[")) {
                require(string.endsWith("]")) {
                    "Expected IP-literal to be enclosed in brackets, but got `$string`."
                }
                val trimmed = string.drop(1).dropLast(1)
                if(trimmed.startsWith("v")) {
                    Rfc3986AuthorityHostIPvFuture(trimmed)
                } else {
                    Rfc3986AuthorityHostIPv6(trimmed)
                }
            } else {
                try {
                    Rfc3986AuthorityHostIPv4(string)
                } catch (it: Throwable) {
                    Rfc3986AuthorityHostRegisteredName(string)
                }
            }
        }
    }
}
package at.asitplus.rfc3986uri

data class Rfc3986UriPathAbsoluteOrEmpty(
    val percentEncodingAwareString: Rfc3986PercentEncodingAwareString,
) : Rfc3986UriPath, Rfc3986RelativeReferencePath {
    init {
        super<Rfc3986UriPath>.validate()
        super<Rfc3986RelativeReferencePath>.validate()
        require(string.isEmpty() || string.startsWith("/")) {
            "Expected path to be empty or start with `/`, but got `$string`."
        }
    }

    constructor(string: String) : this(Rfc3986PercentEncodingAwareString(string))

    fun decode() = percentEncodingAwareString.decode()

    val string: String
        get() = percentEncodingAwareString.string

    override fun toString() = string

    override fun equals(other: Any?) = equalsPath(other)

    override fun hashCode() = toString().hashCode()
}
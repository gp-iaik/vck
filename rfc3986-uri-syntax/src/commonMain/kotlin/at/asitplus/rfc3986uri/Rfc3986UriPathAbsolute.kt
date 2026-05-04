package at.asitplus.rfc3986uri

data class Rfc3986UriPathAbsolute(
    val percentEncodingAwareString: Rfc3986PercentEncodingAwareString
) : Rfc3986UriPath, Rfc3986RelativeReferencePath {
    init {
        super<Rfc3986UriPath>.validate()
        super<Rfc3986RelativeReferencePath>.validate()
        require(string.startsWith("/")) {
            "Expected path to start with `/`, but got `$string`."
        }
        require(string.length >= 2 && string[1] != '/') {
            "Expected path to start with a non-empty segment after root, but got `$string`."
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
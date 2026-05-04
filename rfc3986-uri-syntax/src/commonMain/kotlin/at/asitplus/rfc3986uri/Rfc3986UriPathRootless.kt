package at.asitplus.rfc3986uri

data class Rfc3986UriPathRootless(
    val percentEncodingAwareString: Rfc3986PercentEncodingAwareString,
) : Rfc3986UriPath {
    init {
        super.validate()
        require(string.isNotEmpty() && string[0] != '/') {
            "Expected path to start with a non-empty segment, but got `$string`."
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
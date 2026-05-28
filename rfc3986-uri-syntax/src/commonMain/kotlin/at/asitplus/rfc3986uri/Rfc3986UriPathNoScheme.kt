package at.asitplus.rfc3986uri

data class Rfc3986UriPathNoScheme(
    val percentEncodingAwareString: Rfc3986PercentEncodingAwareString
) : Rfc3986RelativeReferencePath {
    init {
        super.validate()
        require(string.isNotEmpty() && string[0] != '/') {
            "Expected path to start with a non-empty segment, but got `$string`."
        }
        string.indexOf(':').takeIf {
            it != -1
        }?.let { colonIdx ->
            // if there is a colon, it must not be in the first segment — a slash must exist and precede the colon
            val slashIdx = string.indexOf('/')
            require(slashIdx != -1 && slashIdx < colonIdx) {
                "Expected first segment to not contain a colon, `$string`."
            }
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
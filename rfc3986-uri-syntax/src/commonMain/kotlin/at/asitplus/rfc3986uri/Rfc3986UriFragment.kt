package at.asitplus.rfc3986uri

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class Rfc3986UriFragment(
    /**
     *    query         = *( pchar / "/" / "?" )
     */
    val percentEncodingAwareString: Rfc3986PercentEncodingAwareString,
) {
    init {
        string.forEachIndexed { index, it ->
            require(Rfc3986Grammar.isPCharLikeCharacter(it) || it in "/?") {
                "Expected fragment to consist of pchar, `/` and `?`, but got `$it` at index $index in `$string`"
            }
        }
    }

    fun decode() = percentEncodingAwareString.decode()

    constructor(string: String) : this(Rfc3986PercentEncodingAwareString(string))

    val string: String
        get() = percentEncodingAwareString.string

    override fun toString() = string
}
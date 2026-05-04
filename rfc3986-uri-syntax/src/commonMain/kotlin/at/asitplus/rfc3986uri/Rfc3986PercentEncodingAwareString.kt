package at.asitplus.rfc3986uri

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = Rfc3986PercentEncodingAwareString.InlineSerializer::class)
data class Rfc3986PercentEncodingAwareString(
    val string: String
) {
    init {
        requirePercentEncodingConsistence(string)
    }

    /**
     * Decodes percent-encoded string assuming octets are UTF-8 octets.
     */
    fun decode(): String {
        val parts = string.split("%")
        val merged = parts.subList(1, parts.size).fold(listOf(parts.first()) to ByteArray(0)) { acc, part ->
            val encodedUppercase = part.substring(0, 2).toInt(16).toByte()
            val consecutiveOctets = acc.second + encodedUppercase
            if(part.length > 2) {
                // this is the end of a consecutive octet sequence
                (acc.first + consecutiveOctets.decodeToString() + part.substring(2)) to ByteArray(0)
            } else {
                acc.first to consecutiveOctets
            }
        }
        return (merged.first + merged.second.decodeToString()).joinToString("")
    }

    class InlineSerializer : KSerializer<Rfc3986PercentEncodingAwareString> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = InlineSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING,
            )

        override fun serialize(
            encoder: Encoder,
            value: Rfc3986PercentEncodingAwareString
        ) {
            encoder.encodeString(value.string)
        }

        override fun deserialize(decoder: Decoder) = Rfc3986PercentEncodingAwareString(
            decoder.decodeString()
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Rfc3986PercentEncodingAwareString

        return string.percentEncodedUppercaseListRepresentation().joinToString("%").compareTo(
            other.string.percentEncodedUppercaseListRepresentation().joinToString("%")
        ) == 0
    }

    override fun hashCode() = string.percentEncodedUppercaseListRepresentation().hashCode()

    override fun toString() = string

    companion object {
        fun requirePercentEncodingConsistence(string: String) {
            val percentIndices = string.mapIndexedNotNull { index, char ->
                index.takeIf {
                    char == '%'
                }
            }
            percentIndices.forEach { index ->
                string.substring((index + 1)..(index + 2)).forEachIndexed { index2, it ->
                    require(Rfc3986Grammar.isHexDigit(it)) {
                        "Expected percent encoded character to be represented by hexadecimal digits (0-9, a-f, A-F), but got `$it` at index ${index + 1 + index2} in `$string`"
                    }
                }
            }
        }
    }

    private fun String.percentEncodedUppercaseListRepresentation() = split("%").mapIndexed { index, string ->
        if (index == 0) {
            string
        } else {
            val encodedUppercase = string.substring(0, 2).uppercase()
            val encodedChar = Char(encodedUppercase.toInt(16))
            if(Rfc3986Grammar.isUnreserved(encodedChar)) {
                encodedChar.toString()
            } else {
                encodedUppercase
            } + string.substring(2)
        }
    }
}
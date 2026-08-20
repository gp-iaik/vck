package at.asitplus.wallet.lib.oidvci

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.ktor.http.*
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonUnquotedLiteral
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.serializer

typealias Parameters = Map<String, String>

fun <T> Parameters.decode(deserializer: DeserializationStrategy<T>): T =
    deserializer.descriptor.let { descriptor ->
        jsonForParameters.decodeFromJsonElement(deserializer, JsonObject(entries.associate { (k, v) ->
            // ponytail: `v[0]` throwing on an empty value is load-bearing: `ResponseParser` relies on it to fall back
            // from parsing an input as URL to parsing it as POST body
            k to when {
                // members declared as strings keep their content verbatim, even if that content happens to be JSON
                // itself, e.g. `wallet_metadata` of `at.asitplus.openid.RequestObjectParameters`
                descriptor.isStringElement(k) -> JsonPrimitive(v)
                v[0] == '{' -> jsonForParameters.decodeFromString<JsonObject>(v)
                v[0] == '[' -> jsonForParameters.decodeFromString<JsonArray>(v)
                else -> JsonUnquotedLiteral(v)  //no quoted → can be any type for deserializing. requires lenient parsing
            }
        }))
    }

inline fun <reified T> Parameters.decode(): T =
    decode(jsonForParameters.serializersModule.serializer<T>())

/** Whether the member serialized as [name] is a string, for descriptors that have members at all. */
@OptIn(ExperimentalSerializationApi::class)
fun SerialDescriptor.isStringElement(name: String): Boolean = catchingUnwrapped {
    getElementIndex(name).let {
        it != CompositeDecoder.UNKNOWN_NAME && getElementDescriptor(it).kind == PrimitiveKind.STRING
    }
}.getOrElse { false }

inline fun <reified T> Parameters.decodeFromUrlQuery(): T =
    entries.filter { (k, v) -> k.isNotEmpty() && v.isNotEmpty() }
        .associate { (k, v) -> k.safeDecodeUrlQueryComponent() to v.safeDecodeUrlQueryComponent() }.decode()

inline fun <reified T> String.decodeFromPostBody(): T = split("&")
    .associate {
        val key = it.substringBefore("=")
        val value = it.substringAfter("=", "")
        key.safeDecodeUrlQueryComponent(plusIsSpace = true) to value.safeDecodeUrlQueryComponent(plusIsSpace = true)
    }
    .decode()


inline fun <reified T> String.decodeFromUrlQuery(): T = split("&")
    .associate {
        val key = it.substringBefore("=")
        val value = it.substringAfter("=", "")
        key.safeDecodeUrlQueryComponent(plusIsSpace = true) to
                value.safeDecodeUrlQueryComponent(plusIsSpace = true)
    }
    .decode()

/**
 * Empty strings can not be decoded by [decodeURLQueryComponent], so we'll need to filter it.
 */
fun String.safeDecodeUrlQueryComponent(plusIsSpace: Boolean = false) =
    if (this.isNotEmpty()) decodeURLQueryComponent(plusIsSpace = plusIsSpace) else this

fun Parameters.formUrlEncode() = map { (k, v) -> k to v }.formUrlEncode()

inline fun <reified T> T.encodeToParameters(): Parameters =
    when (val element = jsonForParameters.encodeToJsonElement(this)) {
        is JsonArray -> element.mapIndexed { i, v -> i.toString() to v }
        is JsonObject -> element.map { (k, v) -> k to v }
        else -> throw SerializationException("Literals are not supported")
    }.associate { (key, value) ->
        key to if (value is JsonPrimitive) value.content else jsonForParameters.encodeToString(value)
    }


/**
 * The important bit here compared to other instances is `isLenient=true` to be able to decode URL query parameters
 */
val jsonForParameters by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = true
        explicitNulls = false
        ignoreUnknownKeys = true
        isLenient = true
        serializersModule = joseCompliantSerializer.serializersModule
    }
}
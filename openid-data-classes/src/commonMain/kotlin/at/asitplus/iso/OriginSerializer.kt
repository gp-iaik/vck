package at.asitplus.iso

import at.asitplus.catching

/**
 * Serializes an HTTP(S) origin string as defined in
 * https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin.
 */
fun String.serializeHttpHttpsOrigin(): String? = catching {
    // Ktor assigns synthetic host values to some opaque URLs, so check the scheme explicitly.
    val url = io.ktor.http.Url(this)
    val scheme = url.protocol.name.lowercase()
    if (scheme != "http" && scheme != "https") return@catching null
    if (url.host.isBlank()) return@catching null
    val host = url.host.lowercase()
    val defaultPort = url.protocol.defaultPort
    val port = url.port
    buildString {
        append(scheme)
        append("://")
        append(host)
        if (port != defaultPort) {
            append(":")
            append(port)
        }
    }
}.getOrNull()

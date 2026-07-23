package at.asitplus.data.validation.third_party.kotlin.collections

@Throws(IllegalArgumentException::class)
fun <T> kotlin.collections.Collection<T>.requireIsNotEmpty() {
    require(isNotEmpty()) { "Collection must not be empty." }
}

@Throws(IllegalArgumentException::class)
inline fun <T> kotlin.collections.Collection<T>?.requireIsNotNullOrEmpty(
    lazyMessage: () -> Any = { "Collection must neither be null nor empty." },
) {
    require(!isNullOrEmpty(), lazyMessage)
}

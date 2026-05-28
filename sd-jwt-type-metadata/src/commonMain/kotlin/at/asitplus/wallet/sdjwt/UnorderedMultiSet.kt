package at.asitplus.wallet.sdjwt

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Basically used as proxy for equality check in data classes, where the order of a list does not impact equality,
 * but the number of occurances does.
 */
data class UnorderedMultiSet<T>(
    private val list: List<T>,
): Iterable<T> by list {
    constructor(): this(listOf())

    constructor(
        element1: T,
        element2: T,
        vararg elements: T
    ) : this(listOf(element1, element2, *elements))

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UnorderedMultiSet<*>) return false

        if (multiplicities != other.multiplicities) return false

        return true
    }

    override fun hashCode(): Int {
        val result = multiplicities.hashCode()
        return result
    }

    private val multiplicities by lazy {
        list.groupingBy { it }.eachCount()
    }

    class ListSerializer<T>(elementSerializer: KSerializer<T>): KSerializer<UnorderedMultiSet<T>> {
        private val delegate = kotlinx.serialization.builtins.ListSerializer(elementSerializer)
        override val descriptor: SerialDescriptor
            get() = delegate.descriptor

        override fun serialize(
            encoder: Encoder,
            value: UnorderedMultiSet<T>
        ) {
            encoder.encodeSerializableValue(
                delegate,
                value.list
            )
        }

        override fun deserialize(decoder: Decoder): UnorderedMultiSet<T> {
            return UnorderedMultiSet(
                decoder.decodeSerializableValue(delegate)
            )
        }
    }
}
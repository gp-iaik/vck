package at.asitplus.dcapi.issuance

import at.asitplus.openid.CredentialOffer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer

/** Decodes Digital Credentials API issuance options from their JSON representation. */
fun String.decodeDigitalCredentialCreationOptions(): DigitalCredentialCreationOptions =
    joseCompliantSerializer.decodeFromString(this)

/** Decodes issuance options and returns their only credential offer. */
fun String.decodeSingleDigitalCredentialOffer(): CredentialOffer =
    decodeDigitalCredentialCreationOptions().singleCredentialOffer()

/**
 * Returns the only credential offer in these options. (Currently only one offer is supported)
 *
 * @throws IllegalArgumentException if the options contain zero or multiple requests.
 */
fun DigitalCredentialCreationOptions.singleCredentialOffer(): CredentialOffer {
    require(requests.size == 1) { "Only one request supported" }
    return requests.first().data
}

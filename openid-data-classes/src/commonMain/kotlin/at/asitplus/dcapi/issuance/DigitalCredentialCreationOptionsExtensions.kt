package at.asitplus.dcapi.issuance

import at.asitplus.openid.CredentialOffer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer

fun String.decodeDigitalCredentialCreationOptions(): DigitalCredentialCreationOptions =
    joseCompliantSerializer.decodeFromString(this)

fun String.decodeSingleDigitalCredentialOffer(): CredentialOffer =
    decodeDigitalCredentialCreationOptions().singleCredentialOffer()

fun DigitalCredentialCreationOptions.singleCredentialOffer(): CredentialOffer {
    require(requests.size == 1) { "Only one request supported" }
    return requests.first().data
}

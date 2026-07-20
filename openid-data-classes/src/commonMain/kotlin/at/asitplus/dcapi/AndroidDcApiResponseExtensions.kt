package at.asitplus.dcapi

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer

/**
 * Encodes the complete protocol-discriminated response as JSON for Android's Digital Credentials API integration.
 *
 * This function does not depend on Android APIs. Converting Android platform objects such as `Bundle` instances to
 * the request models is the responsibility of the wallet's Android integration.
 */
fun DigitalCredentialInterface.toAndroidDcApiResponseJson(): String =
    joseCompliantSerializer.encodeToString<DigitalCredentialInterface>(this)

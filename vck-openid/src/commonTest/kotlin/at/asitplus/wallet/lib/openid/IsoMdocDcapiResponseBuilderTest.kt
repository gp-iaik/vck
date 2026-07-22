package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
import at.asitplus.dcapi.DCAPIInfo
import at.asitplus.dcapi.DCAPIResponse
import at.asitplus.dcapi.IsoMdocResponse
import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceSignedItem
import at.asitplus.iso.DeviceSignedItemList
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.serializeHttpHttpsOrigin
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.openid.ClaimDescription
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenId4VciClaimsPathPointer
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.toIso180137AnnexCDeviceRequest
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.supreme.asymmetric.HPKE
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.iso.Iso180137AnnexCRequestOptions
import at.asitplus.wallet.lib.iso.Iso180137AnnexCVerifier
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.encodeToByteArray
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

@OptIn(SecretExposure::class)
@Suppress("DEPRECATION")
val IsoMdocDcapiResponseBuilderTest by matrixSuite {
    test("session transcript matches verifier inputs") {
        val fixture = dcapiFixture()

        val walletTranscript = IsoMdocDcapiResponseBuilder.sessionTranscriptFor(fixture.walletRequest)
        val verifierTranscript = at.asitplus.iso.SessionTranscript.forDcApi(
            at.asitplus.dcapi.DCAPIHandover(
                type = TYPE_DCAPI,
                hash = coseCompliantSerializer.encodeToByteArray(
                    DCAPIInfo(
                        encryptionInfo = fixture.walletRequest.parameters.isoMdocRequest.encryptionInfo,
                        serializedOrigin = ORIGIN.serializeHttpHttpsOrigin() ?: error("Invalid origin")
                    )
                ).sha256()
            )
        )

        coseCompliantSerializer.encodeToByteArray(verifierTranscript).contentEquals(
            coseCompliantSerializer.encodeToByteArray(walletTranscript)
        ) shouldBe true
    }

    test("HPKE roundtrip requires same session transcript bytes") {
        val fixture = dcapiFixture()
        val encodedTranscript = coseCompliantSerializer.encodeToByteArray(
            IsoMdocDcapiResponseBuilder.sessionTranscriptFor(fixture.walletRequest)
        )
        val plaintext = "device-response".encodeToByteArray()

        val sealed = hpke.SealBase(
            pkR = fixture.walletRequest.parameters.isoMdocRequest.encryptionInfo.encryptionParameters
                .recipientPublicKey.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC,
            info = encodedTranscript,
            aad = ByteArray(0),
            pt = plaintext,
        )

        decryptHpke(
            enc = sealed.encapsulatedSecret,
            ciphertext = sealed.ciphertext,
            responseEncryptionKeySignum = fixture.verifierKey.exportPrivateKey().getOrThrow()
                    as CryptoPrivateKey.EC.WithPublicKey,
            cborEncodedSessionTranscript = encodedTranscript,
        ).contentEquals(plaintext) shouldBe true

        shouldThrowAny {
            decryptHpke(
                enc = sealed.encapsulatedSecret,
                ciphertext = sealed.ciphertext,
                responseEncryptionKeySignum = fixture.verifierKey.exportPrivateKey().getOrThrow()
                        as CryptoPrivateKey.EC.WithPublicKey,
                cborEncodedSessionTranscript = encodedTranscript + byteArrayOf(0x00),
            )
        }
    }

    test("device authentication payload keeps device namespace bytes stable") {
        val fixture = dcapiFixture()
        val deviceNameSpaceBytes = ByteStringWrapper(
            DeviceNameSpaces(
                mapOf(
                    ConstantIndex.AtomicAttribute2023.isoNamespace to DeviceSignedItemList(
                        listOf(DeviceSignedItem(ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME, "Susanne"))
                    )
                )
            )
        )
        val deviceAuthentication = DeviceAuthentication(
            type = DeviceAuthentication.TYPE,
            sessionTranscript = IsoMdocDcapiResponseBuilder.sessionTranscriptFor(fixture.walletRequest),
            docType = ConstantIndex.AtomicAttribute2023.isoDocType,
            namespaces = deviceNameSpaceBytes,
        )

        val walletSidePayload = coseCompliantSerializer
            .encodeToByteArray(ByteStringWrapper(deviceAuthentication))
            .wrapInCborTag(24)
        val verifierSidePayload = coseCompliantSerializer
            .encodeToByteArray(coseCompliantSerializer.encodeToByteArray(deviceAuthentication))
            .wrapInCborTag(24)

        walletSidePayload.contentEquals(verifierSidePayload) shouldBe true
    }

    test("encrypted Annex C response validates device signature") {
        val fixture = dcapiFixture()
        val holderKey = EphemeralKeyWithoutCert()
        val holderAgent = HolderAgent(holderKey)
        holderAgent.storeCredential(
            IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
            ).issueCredential(isoCredential(holderKey.publicKey))
                .getOrThrow()
                .toStoreCredentialInput()
        ).getOrThrow()

        val encryptedResponse = IsoMdocDcapiResponseBuilder.buildEncryptedResponse(
            credentialPresentation = fixture.presentationRequestBuilder.toPresentationExchangeRequest()
                .toCredentialPresentation() as CredentialPresentation.PresentationExchangePresentation,
            isoMdocWalletRequest = fixture.walletRequest,
            keyMaterial = holderKey,
            holder = holderAgent,
        )

        val verified = fixture.verifier.validateResponse(
            receivedData = DCAPIResponse(encryptedResponse),
            externalId = STATE,
            decryptHpke = ::decryptHpke,
            expectedOrigin = ORIGIN,
        ).getOrThrow()

        verified.documents.shouldNotBeEmpty()
    }

    test("encrypted Annex C response contains all requested documents") {
        val fixture = dcapiFixture(
            listOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    attributePaths = setOf(
                        DCQLClaimsPathPointer(ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME)
                    ),
                ),
                RequestOptionsCredential(
                    credentialScheme = SecondAtomicAttribute,
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    attributePaths = setOf(DCQLClaimsPathPointer(SecondAtomicAttribute.CLAIM_FAMILY_NAME)),
                ),
            )
        )
        val holderKey = EphemeralKeyWithoutCert()
        val holderAgent = HolderAgent(holderKey)
        val issuer = IssuerAgent(
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
            identifier = "https://issuer.example.com/".toUri(),
        )
        listOf(
            isoCredential(holderKey.publicKey),
            isoCredential(
                subjectPublicKey = holderKey.publicKey,
                scheme = SecondAtomicAttribute,
                elementIdentifier = SecondAtomicAttribute.CLAIM_FAMILY_NAME,
                elementValue = "Meier",
            ),
        ).forEach { credential ->
            holderAgent.storeCredential(
                issuer.issueCredential(credential).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()
        }

        val encryptedResponse = IsoMdocDcapiResponseBuilder.buildEncryptedResponse(
            credentialPresentation = fixture.presentationRequestBuilder.toPresentationExchangeRequest()
                .toCredentialPresentation() as CredentialPresentation.PresentationExchangePresentation,
            isoMdocWalletRequest = fixture.walletRequest,
            keyMaterial = holderKey,
            holder = holderAgent,
        )

        fixture.verifier.validateResponse(
            receivedData = DCAPIResponse(encryptedResponse),
            externalId = STATE,
            decryptHpke = ::decryptHpke,
            expectedOrigin = ORIGIN,
        ).getOrThrow().documents.shouldHaveSize(2)
    }

    test("Annex C holder creates presentation request") {
        val fixture = dcapiFixture()

        val presentationRequest = Iso180137AnnexCHolder()
            .createPresentationRequest(fixture.walletRequest)
            .getOrThrow()

        presentationRequest.presentationDefinition.inputDescriptors.single().id shouldBe
                ConstantIndex.AtomicAttribute2023.isoDocType
    }

    test("Annex C holder finalizes encrypted response") {
        val fixture = dcapiFixture()
        val holderKey = EphemeralKeyWithoutCert()
        val holderAgent = HolderAgent(holderKey)
        holderAgent.storeCredential(
            IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
            ).issueCredential(isoCredential(holderKey.publicKey))
                .getOrThrow()
                .toStoreCredentialInput()
        ).getOrThrow()

        val encryptedResponse = Iso180137AnnexCHolder(
            keyMaterial = holderKey,
            holder = holderAgent,
        ).finalizeResponse(
            request = fixture.walletRequest,
            credentialPresentation = fixture.presentationRequestBuilder.toPresentationExchangeRequest()
                .toCredentialPresentation() as CredentialPresentation.PresentationExchangePresentation,
        ).getOrThrow()

        val verified = fixture.verifier.validateResponse(
            receivedData = DCAPIResponse(encryptedResponse),
            externalId = STATE,
            decryptHpke = ::decryptHpke,
            expectedOrigin = ORIGIN,
        ).getOrThrow()

        verified.documents.shouldNotBeEmpty()
    }

    test("DC API holder dispatches and finalizes Annex C requests") {
        val fixture = dcapiFixture()
        val holderKey = EphemeralKeyWithoutCert()
        val holderAgent = HolderAgent(holderKey)
        holderAgent.storeCredential(
            IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
            ).issueCredential(isoCredential(holderKey.publicKey))
                .getOrThrow()
                .toStoreCredentialInput()
        ).getOrThrow()
        val dcApiHolder = DcApiHolder(
            keyMaterial = holderKey,
            holder = holderAgent,
        )

        val state = dcApiHolder.startAuthorizationResponsePreparation(fixture.walletRequest)
            .getOrThrow()
            .shouldBeInstanceOf<DcApiPreparationState.Iso180137AnnexC>()
        val response = dcApiHolder.finalizeAuthorizationResponse(
            state = state,
            credentialPresentation = fixture.presentationRequestBuilder.toPresentationExchangeRequest()
                .toCredentialPresentation(),
        ).getOrThrow().shouldBeInstanceOf<IsoMdocResponse>()

        fixture.verifier.validateResponse(
            receivedData = response.data,
            externalId = STATE,
            decryptHpke = ::decryptHpke,
            expectedOrigin = ORIGIN,
        ).getOrThrow().documents.shouldNotBeEmpty()
    }
}

private suspend fun dcapiFixture(
    requestOptions: List<RequestOptionsCredential> = listOf(
        RequestOptionsCredential(
            credentialScheme = ConstantIndex.AtomicAttribute2023,
            representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
            attributePaths = setOf(DCQLClaimsPathPointer(ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME)),
        )
    )
): DcapiFixture {
    val verifierKey = EphemeralKeyWithoutCert()
    val verifier = Iso180137AnnexCVerifier(decryptionKeyMaterial = verifierKey)
    val presentationRequestBuilder = CredentialPresentationRequestBuilder(requestOptions)
    val isoRequest = verifier.createRequest(
        Iso180137AnnexCRequestOptions(
            deviceRequest = presentationRequestBuilder.toDCQLRequest()!!.dcqlQuery.toIso180137AnnexCDeviceRequest(),
            state = STATE,
        )
    )
    return DcapiFixture(
        verifier = verifier,
        verifierKey = verifierKey,
        presentationRequestBuilder = presentationRequestBuilder,
        walletRequest = RequestParametersFrom.IsoMdocDcApi(
            parameters = RequestParametersFrom.IsoMdocDcApi.IsoMdocRequestWrapper(isoRequest),
            jsonString = joseCompliantSerializer.encodeToString(isoRequest),
            callingOrigin = ORIGIN,
            credentialIds = null,
        )
    )
}

private fun isoCredential(
    subjectPublicKey: CryptoPublicKey,
    scheme: IsoMdocCredentialScheme = ConstantIndex.AtomicAttribute2023,
    elementIdentifier: String = ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME,
    elementValue: String = "Susanne",
) =
    CredentialToBeIssued.Iso(
        issuerSignedItems = listOf(
            IssuerSignedItem(
                digestId = 0U,
                random = Random.nextBytes(16),
                elementIdentifier = elementIdentifier,
                elementValue = elementValue,
            )
        ),
        expiration = Clock.System.now() + 10.minutes,
        scheme = scheme,
        subjectPublicKey = subjectPublicKey,
        userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
    )

private object SecondAtomicAttribute : IsoMdocCredentialScheme {
    const val CLAIM_FAMILY_NAME = "family_name"

    override val isoNamespace: String = "at.a-sit.wallet.atomic-attribute-2025"
    override val isoDocType: String = "at.a-sit.wallet.atomic-attribute-2025.iso"
    override val claimDescriptions: Set<ClaimDescription> =
        setOf(ClaimDescription(OpenId4VciClaimsPathPointer(CLAIM_FAMILY_NAME)))
}

private data class DcapiFixture(
    val verifier: Iso180137AnnexCVerifier,
    val verifierKey: EphemeralKeyWithoutCert,
    val presentationRequestBuilder: CredentialPresentationRequestBuilder,
    val walletRequest: RequestParametersFrom.IsoMdocDcApi,
)

@OptIn(SecretExposure::class)
private suspend fun decryptHpke(
    enc: ByteArray,
    ciphertext: ByteArray,
    responseEncryptionKeySignum: CryptoPrivateKey.EC.WithPublicKey,
    cborEncodedSessionTranscript: ByteArray,
): ByteArray =
    hpke.OpenBase(
        enc = enc,
        skR = responseEncryptionKeySignum,
        info = cborEncodedSessionTranscript,
        aad = byteArrayOf(),
        ct = ciphertext,
    )

private val hpke = HPKE(
    HPKE.KEM.DHKEM_P256_HKDF_SHA256,
    HPKE.KDF.HKDF_SHA256,
    HPKE.AEAD.AES_128_GCM,
)

private const val ORIGIN = "https://verifier.example.com"
private const val STATE = "state"

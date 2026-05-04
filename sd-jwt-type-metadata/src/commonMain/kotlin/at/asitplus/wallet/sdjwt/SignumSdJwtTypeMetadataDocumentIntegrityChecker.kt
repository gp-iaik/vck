package at.asitplus.wallet.sdjwt

// unused because we don't yet have test data for this, but the delegate has been tested
object SignumSdJwtTypeMetadataDocumentIntegrityChecker :
    SdJwtTypeMetadataDocumentIntegrityChecker by DelegatingSdJwtTypeMetadataDocumentIntegrityChecker(
        subresourceIntegrityChecker = SignumW3cSubresourceIntegrityChecker
    )
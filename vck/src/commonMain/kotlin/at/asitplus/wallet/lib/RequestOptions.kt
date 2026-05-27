package at.asitplus.wallet.lib

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.ConstraintFilter
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.RequirementEnum
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.NameSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLCredentialQuery
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import com.benasher44.uuid.uuid4
import kotlinx.serialization.json.JsonPrimitive

typealias RequestedAttributes = Set<String>
typealias RequestedAttributePaths = Set<DCQLClaimsPathPointer>

interface RequestOptions {
    val state: String
}

data class RequestOptionsCredential(
    /** Credential type to request, or `null` to make no restrictions. */
    val credentialScheme: ConstantIndex.CredentialScheme,
    /** Required representation, see [ConstantIndex.CredentialRepresentation]. */
    val representation: CredentialRepresentation = CredentialRepresentation.PLAIN_JWT,
    /**
     * List of attributes that shall be requested explicitly (selective disclosure),
     * or `null` to make no restrictions.
     *
     * Use `address.formatted` to request the `formatted` claim nested inside `address`.
     *
     * Use [attributePaths] for literal claim names containing dots.
     */
    @Deprecated(
        "Use attributePaths. Strings are kept as dot-splitting nested-path shorthand.",
        ReplaceWith("attributePaths")
    )
    val requestedAttributes: RequestedAttributes? = null,
    /**
     * List of attributes that shall be requested explicitly (selective disclosure),
     * but are not required (i.e. marked as optional), or `null` to make no restrictions.
     *
     * Use `address.formatted` to request the `formatted` claim nested inside `address`.
     *
     * Use [optionalAttributePaths] for literal claim names containing dots.
     */
    @Deprecated(
        "Use optionalAttributePaths. Strings are kept as dot-splitting nested-path shorthand.",
        ReplaceWith("optionalAttributePaths")
    )
    val requestedOptionalAttributes: RequestedAttributes? = null,
    /** ID to be used in [DifInputDescriptor], or [DCQLCredentialQuery] */
    val id: String = uuid4().toString(),
    /**
     * List of JSON claim paths that shall be requested explicitly (selective disclosure),
     * or `null` to make no restrictions.
     *
     * Use `DCQLClaimsPathPointer("address.region")` to request a flat claim with a literal dot in its name.
     * Use `DCQLClaimsPathPointer("address", "region")` to request `region` nested inside `address`.
     */
    val attributePaths: RequestedAttributePaths? = null,
    /**
     * List of JSON claim paths that shall be requested explicitly (selective disclosure),
     * but are not required (i.e. marked as optional), or `null` to make no restrictions.
     *
     * Use `DCQLClaimsPathPointer("address.region")` to request a flat claim with a literal dot in its name.
     * Use `DCQLClaimsPathPointer("address", "region")` to request `region` nested inside `address`.
     */
    val optionalAttributePaths: RequestedAttributePaths? = null,
) {
    fun buildId() = if (isMdoc) credentialScheme.isoDocType!! else id

    private val isMdoc: Boolean
        get() = credentialScheme.isoDocType != null && representation == CredentialRepresentation.ISO_MDOC

    /** To be used for Presentation Exchange in [DifInputDescriptor.constraints] */
    fun toConstraint() = Constraint(
        limitDisclosure = if (isMdoc) RequirementEnum.REQUIRED else null,
        fields = (requiredAttributes() + optionalAttributes() + toTypeConstraint()).filterNotNull().toSet()
    )

    @Suppress("DEPRECATION")
    private fun requiredAttributes() =
        effectiveRequestedAttributePaths().createConstraints(credentialScheme, false)

    @Suppress("DEPRECATION")
    private fun optionalAttributes() =
        effectiveRequestedOptionalAttributePaths().createConstraints(credentialScheme, true)

    private fun toTypeConstraint() = when (representation) {
        CredentialRepresentation.PLAIN_JWT -> credentialScheme.toVcConstraint()
        CredentialRepresentation.SD_JWT -> credentialScheme.toSdJwtConstraint()
        CredentialRepresentation.ISO_MDOC -> null
    }

    fun toFormatHolder(containerJwt: FormatContainerJwt, containerSdJwt: FormatContainerSdJwt) =
        when (representation) {
            CredentialRepresentation.PLAIN_JWT -> FormatHolder(jwtVp = containerJwt)
            CredentialRepresentation.SD_JWT -> FormatHolder(sdJwt = containerSdJwt)
            CredentialRepresentation.ISO_MDOC -> FormatHolder(msoMdoc = containerJwt)
        }

    @Suppress("DEPRECATION")
    fun effectiveRequestedAttributePaths(): RequestedAttributePaths =
        (attributePaths ?: emptySet()) + requestedAttributes.toNestedClaimPaths()

    @Suppress("DEPRECATION")
    fun effectiveRequestedOptionalAttributePaths(): RequestedAttributePaths =
        (optionalAttributePaths ?: emptySet()) + requestedOptionalAttributes.toNestedClaimPaths()

    private fun RequestedAttributes?.toNestedClaimPaths(): RequestedAttributePaths =
        this?.map { it.splitByDotToDcqlPath() }?.toSet() ?: emptySet()

    private fun String.splitByDotToDcqlPath() = DCQLClaimsPathPointer(
        split(".").map { DCQLClaimsPathPointerSegment.NameSegment(it) }.toNonEmptyList()
    )

    private fun RequestedAttributePaths.createConstraints(
        scheme: ConstantIndex.CredentialScheme?,
        optional: Boolean,
    ): Collection<ConstraintField> = map {
        if (isMdoc) it.toIsoMdocConstraintField(scheme, optional) else it.toJwtConstraintField(optional)
    }

    private fun DCQLClaimsPathPointer.toIsoMdocConstraintField(
        scheme: ConstantIndex.CredentialScheme?,
        optional: Boolean,
    ) =
        ConstraintField(
            path = listOf(toIsoMdocClaimPath(scheme).toNormalizedJsonPath().toString()),
            intentToRetain = false,
            optional = optional
        )

    private fun DCQLClaimsPathPointer.toJwtConstraintField(optional: Boolean): ConstraintField =
        ConstraintField(path = listOf(toNormalizedJsonPath().toString()), optional = optional)

    private fun DCQLClaimsPathPointer.toNormalizedJsonPath(): NormalizedJsonPath =
        NormalizedJsonPath(segments.map {
            when (it) {
                is DCQLClaimsPathPointerSegment.NameSegment -> NameSegment(it.name)
                is DCQLClaimsPathPointerSegment.IndexSegment -> NormalizedJsonPathSegment.IndexSegment(it.index)
                DCQLClaimsPathPointerSegment.NullSegment ->
                    throw IllegalArgumentException("Presentation Exchange constraints do not support null path segments")
            }
        })

    private fun ConstantIndex.CredentialScheme.toVcConstraint() = if (supportsVcJwt)
        ConstraintField(
            path = listOf("$.type"),
            filter = ConstraintFilter(
                type = "string",
                const = JsonPrimitive(vcType),
            )
        ) else null

    private fun ConstantIndex.CredentialScheme.toSdJwtConstraint() = if (supportsSdJwt)
        ConstraintField(
            path = listOf("$.vct"),
            filter = ConstraintFilter(
                type = "string",
                const = JsonPrimitive(sdJwtType!!)
            )
        ) else null
}

fun DCQLClaimsPathPointer.toIsoMdocClaimPath(
    scheme: ConstantIndex.CredentialScheme?,
): DCQLClaimsPathPointer {
    require(segments.all { it is DCQLClaimsPathPointerSegment.NameSegment }) {
        "ISO mdoc requested attribute paths must contain only name segments"
    }
    return when (segments.size) {
        1 -> DCQLClaimsPathPointer(
            scheme?.isoNamespace ?: "mdoc",
            (segments.first() as DCQLClaimsPathPointerSegment.NameSegment).name,
        )

        2 -> this
        else -> throw IllegalArgumentException(
            "ISO mdoc requested attribute paths must contain a claim name or a namespace and claim name"
        )
    }
}

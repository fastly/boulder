// Code generated by "stringer -type=FeatureFlag"; DO NOT EDIT.

package features

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[unused-0]
	_ = x[CAAValidationMethods-1]
	_ = x[CAAAccountURI-2]
	_ = x[EnforceMultiVA-3]
	_ = x[MultiVAFullResults-4]
	_ = x[MandatoryPOSTAsGET-5]
	_ = x[ECDSAForAll-6]
	_ = x[ServeRenewalInfo-7]
	_ = x[AllowReRevocation-8]
	_ = x[MozRevocationReasons-9]
	_ = x[OldTLSOutbound-10]
	_ = x[OldTLSInbound-11]
	_ = x[SHA1CSRs-12]
	_ = x[AllowUnrecognizedFeatures-13]
	_ = x[ExpirationMailerDontLookTwice-14]
}

const _FeatureFlag_name = "unusedCAAValidationMethodsCAAAccountURIEnforceMultiVAMultiVAFullResultsMandatoryPOSTAsGETECDSAForAllServeRenewalInfoAllowReRevocationMozRevocationReasonsOldTLSOutboundOldTLSInboundSHA1CSRsAllowUnrecognizedFeaturesExpirationMailerDontLookTwice"

var _FeatureFlag_index = [...]uint8{0, 6, 26, 39, 53, 71, 89, 100, 116, 133, 153, 167, 180, 188, 213, 242}

func (i FeatureFlag) String() string {
	if i < 0 || i >= FeatureFlag(len(_FeatureFlag_index)-1) {
		return "FeatureFlag(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _FeatureFlag_name[_FeatureFlag_index[i]:_FeatureFlag_index[i+1]]
}

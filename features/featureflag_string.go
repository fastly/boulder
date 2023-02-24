// Code generated by "stringer -type=FeatureFlag"; DO NOT EDIT.

package features

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[unused-0]
	_ = x[StoreRevokerInfo-1]
	_ = x[CAAValidationMethods-2]
	_ = x[CAAAccountURI-3]
	_ = x[EnforceMultiVA-4]
	_ = x[MultiVAFullResults-5]
	_ = x[ECDSAForAll-6]
	_ = x[ServeRenewalInfo-7]
	_ = x[AllowUnrecognizedFeatures-8]
	_ = x[ROCSPStage6-9]
	_ = x[ROCSPStage7-10]
	_ = x[ExpirationMailerUsesJoin-11]
	_ = x[CertCheckerChecksValidations-12]
	_ = x[CertCheckerRequiresValidations-13]
	_ = x[AsyncFinalize-14]
}

const _FeatureFlag_name = "unusedStoreRevokerInfoCAAValidationMethodsCAAAccountURIEnforceMultiVAMultiVAFullResultsECDSAForAllServeRenewalInfoAllowUnrecognizedFeaturesROCSPStage6ROCSPStage7ExpirationMailerUsesJoinCertCheckerChecksValidationsCertCheckerRequiresValidationsAsyncFinalize"

var _FeatureFlag_index = [...]uint16{0, 6, 22, 42, 55, 69, 87, 98, 114, 139, 150, 161, 185, 213, 243, 256}

func (i FeatureFlag) String() string {
	if i < 0 || i >= FeatureFlag(len(_FeatureFlag_index)-1) {
		return "FeatureFlag(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _FeatureFlag_name[_FeatureFlag_index[i]:_FeatureFlag_index[i+1]]
}

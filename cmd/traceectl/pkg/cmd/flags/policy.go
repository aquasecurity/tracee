package flags

const PolicyFlag = "policy"
const DefaultPolicy = ""

func PreparePolicy(policySlice []string) ([]string, error) {
	// currently there isn't any way to identify when a policy isn't valid, so pass all
	return policySlice, nil
}

package filterscope

import "fmt"

func FilterScopeNilError() error {
	return fmt.Errorf("filter scope cannot be nil")
}

func FilterScopeNotFoundError(idx int) error {
	return fmt.Errorf("filter scope not found at index [%d]", idx)
}

func FilterScopesMaxExceededError() error {
	return fmt.Errorf("filter scopes maximum exceeded [%d]", MaxFilterScopes)
}

func FilterScopesOutOfRangeError(idx int) error {
	return fmt.Errorf("filter scopes index [%d] out-of-range [0-%d]", idx, MaxFilterScopes-1)
}

func FilterScopeAlreadyExists(scope *FilterScope, id int) error {
	return fmt.Errorf("filter scope [%+v] already set with different id [%d]", scope, id)
}

package trigger

import "fmt"

func NoEventContextError(id uint64) error {
	return fmt.Errorf("no event context with id %d", id)
}

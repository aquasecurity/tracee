package utils

import (
	"math"
)

// RoundToClosestN rounds a number to the closest multiple of n.
func RoundToClosestN(val int, n int) int {
	return int(math.Round(float64(val)/float64(n))) * n
}

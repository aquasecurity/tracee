package types_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/utils/types"
)

var (
	changeTime        = time.Unix(0, 10)
	beforeChangeTime  = changeTime.Add(-time.Nanosecond)
	afterChangingTime = changeTime.Add(time.Nanosecond)
)

func TestNewChangingObj_Get(t *testing.T) {
	t.Run(
		"zero values", func(t *testing.T) {
			t.Run(
				"int", func(t *testing.T) {
					co := types.NewTimeSeries[int](0)
					assert.Equal(t, 0, co.Get(changeTime))
				},
			)
			t.Run(
				"string", func(t *testing.T) {
					co := types.NewTimeSeries[string]("")
					assert.Equal(t, "", co.Get(changeTime))
				},
			)
		},
	)
	t.Run(
		"normal values", func(t *testing.T) {
			t.Run(
				"int", func(t *testing.T) {
					val := 1234
					co := types.NewTimeSeries[int](val)
					assert.Equal(t, val, co.Get(changeTime))
				},
			)
			t.Run(
				"string", func(t *testing.T) {
					val := "hello world"
					co := types.NewTimeSeries[string](val)
					assert.Equal(t, val, co.Get(changeTime))
				},
			)
		},
	)

	t.Run(
		"concurrency", func(t *testing.T) {
			defaultVal := 1234
			co := types.NewTimeSeries[int](defaultVal)
			wg := &sync.WaitGroup{}

			wg.Add(1)
			go func() {
				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func(i int) {
						if i%2 == 0 {
							val := co.Get(changeTime)
							assert.Equal(t, defaultVal, val)
						}
						wg.Done()
					}(i)
				}

				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func(i int) {
						if i%2 != 0 {
							val := co.Get(changeTime)
							assert.Equal(t, defaultVal, val)
						}
						wg.Done()
					}(i)
				}

				wg.Done()
			}()

			wg.Wait()
		},
	)
}

func TestNewChangingObj_ChangeDefault(t *testing.T) {
	t.Run(
		"no values", func(t *testing.T) {
			t.Run(
				"int", func(t *testing.T) {
					newDefault := 1234
					co := types.NewTimeSeries[int](0)
					co.ChangeDefault(newDefault)
					assert.Equal(t, newDefault, co.Get(changeTime))
				},
			)
			t.Run(
				"string", func(t *testing.T) {
					newDefault := "hello world"
					co := types.NewTimeSeries[string]("")
					co.ChangeDefault(newDefault)
					assert.Equal(t, newDefault, co.Get(changeTime))
				},
			)
		},
	)

	t.Run(
		"with values", func(t *testing.T) {
			t.Run(
				"int", func(t *testing.T) {
					newDefault := 1234
					stateVal := 4321
					co := types.NewTimeSeries[int](0)
					co.AddState(
						types.State[int]{
							StartTime: changeTime,
							Val:       stateVal,
						},
					)
					co.ChangeDefault(newDefault)
					assert.Equal(t, newDefault, co.Get(beforeChangeTime))
					assert.Equal(t, stateVal, co.Get(afterChangingTime))
				},
			)
			t.Run(
				"string", func(t *testing.T) {
					newDefault := "hello world"
					stateVal := "change"
					co := types.NewTimeSeries[string]("")
					co.AddState(
						types.State[string]{
							StartTime: changeTime,
							Val:       stateVal,
						},
					)
					co.ChangeDefault(newDefault)
					assert.Equal(t, newDefault, co.Get(beforeChangeTime))
					assert.Equal(t, stateVal, co.Get(afterChangingTime))
				},
			)
		},
	)

	t.Run(
		"concurrency", func(t *testing.T) {
			defaultVal := -1
			co := types.NewTimeSeries[int](defaultVal)
			wg := &sync.WaitGroup{}

			wg.Add(1)
			go func() {
				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func(i int) {
						if i%2 == 0 {
							co.ChangeDefault(i)
						}
						wg.Done()
					}(i)
				}

				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func(i int) {
						if i%2 != 0 {
							co.ChangeDefault(i)
						}
						wg.Done()
					}(i)
				}

				wg.Done()
			}()

			wg.Wait()

			assert.NotEqual(t, defaultVal, co.Get(changeTime))
		},
	)
}

func TestNewChangingObj_AddState(t *testing.T) {
	t.Run(
		"one value", func(t *testing.T) {
			t.Run(
				"int", func(t *testing.T) {
					stateVal := 4321
					co := types.NewTimeSeries[int](0)
					co.AddState(
						types.State[int]{
							StartTime: changeTime,
							Val:       stateVal,
						},
					)
					assert.Equal(t, 0, co.Get(beforeChangeTime))
					assert.Equal(t, stateVal, co.Get(changeTime))
					assert.Equal(t, stateVal, co.Get(afterChangingTime))
				},
			)
			t.Run(
				"string", func(t *testing.T) {
					stateVal := "change"
					co := types.NewTimeSeries[string]("")
					co.AddState(
						types.State[string]{
							StartTime: changeTime,
							Val:       stateVal,
						},
					)
					assert.Equal(t, "", co.Get(beforeChangeTime))
					assert.Equal(t, stateVal, co.Get(changeTime))
					assert.Equal(t, stateVal, co.Get(afterChangingTime))
				},
			)
		},
	)

	t.Run(
		"multiple values", func(t *testing.T) {
			secondChangeTime := time.Unix(0, 20)
			beforeSecondChangeTime := secondChangeTime.Add(-time.Nanosecond)
			afterSecondChangingTime := secondChangeTime.Add(time.Nanosecond)
			t.Run(
				"int", func(t *testing.T) {
					firstState := 1000
					secondState := 2000
					co := types.NewTimeSeries[int](0)
					co.AddState(
						types.State[int]{
							StartTime: changeTime,
							Val:       firstState,
						},
					)
					co.AddState(
						types.State[int]{
							StartTime: secondChangeTime,
							Val:       secondState,
						},
					)
					assert.Equal(t, 0, co.Get(beforeChangeTime))
					assert.Equal(t, firstState, co.Get(changeTime))
					assert.Equal(t, firstState, co.Get(afterChangingTime))
					assert.Equal(t, firstState, co.Get(beforeSecondChangeTime))
					assert.Equal(t, secondState, co.Get(secondChangeTime))
					assert.Equal(t, secondState, co.Get(afterSecondChangingTime))
				},
			)
			t.Run(
				"string", func(t *testing.T) {
					firstState := "change1"
					secondState := "change2"
					co := types.NewTimeSeries[string]("")
					co.AddState(
						types.State[string]{
							StartTime: changeTime,
							Val:       firstState,
						},
					)
					co.AddState(
						types.State[string]{
							StartTime: secondChangeTime,
							Val:       secondState,
						},
					)
					assert.Equal(t, "", co.Get(beforeChangeTime))
					assert.Equal(t, firstState, co.Get(changeTime))
					assert.Equal(t, firstState, co.Get(afterChangingTime))
					assert.Equal(t, firstState, co.Get(beforeSecondChangeTime))
					assert.Equal(t, secondState, co.Get(secondChangeTime))
					assert.Equal(t, secondState, co.Get(afterSecondChangingTime))
				},
			)
		},
	)

	t.Run(
		"concurrency", func(t *testing.T) {
			vals := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
			times := []time.Time{
				time.Unix(0, 10),
				time.Unix(0, 20),
				time.Unix(0, 30),
				time.Unix(0, 40),
				time.Unix(0, 50),
				time.Unix(0, 60),
				time.Unix(0, 70),
				time.Unix(0, 80),
				time.Unix(0, 90),
				time.Unix(0, 100),
			}
			defaultVal := 0
			co := types.NewTimeSeries[int](defaultVal)
			wg := &sync.WaitGroup{}

			wg.Add(1)
			go func() {
				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func(i int) {
						if i%2 == 0 {
							co.AddState(
								types.State[int]{
									StartTime: times[i],
									Val:       vals[i],
								},
							)
						}
						wg.Done()
					}(i)
				}

				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func(i int) {
						if i%2 != 0 {
							co.AddState(
								types.State[int]{
									StartTime: times[i],
									Val:       vals[i],
								},
							)
						}
						wg.Done()
					}(i)
				}

				wg.Done()
			}()

			wg.Wait()

			assert.Equal(t, defaultVal, co.Get(time.Unix(0, 0)))
			for i := 0; i < 10; i++ {
				assert.Equal(t, vals[i], co.Get(times[i]))
			}
		},
	)

}

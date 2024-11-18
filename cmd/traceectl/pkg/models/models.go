package models

type TestCase struct {
	TestName        string
	OutputSlice     []string
	ExpectedPrinter interface{}
	ExpectedError   error
}

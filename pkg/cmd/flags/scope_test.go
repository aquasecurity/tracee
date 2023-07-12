package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseScopeFlag(t *testing.T) {
	testCases := []struct {
		name           string
		flag           string
		expectedResult scopeFlag
		expectedError  error
	}{
		// Valid
		{
			name: "Valid flag without operatorAndValues",
			flag: "filterName",
			expectedResult: scopeFlag{
				full:              "filterName",
				scopeName:         "filterName",
				operatorAndValues: "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag without operatorAndValues",
			flag: "!filterName",
			expectedResult: scopeFlag{
				full:              "!filterName",
				scopeName:         "!filterName",
				operator:          "", // negation is not saved as operator
				values:            "",
				operatorAndValues: "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName=v",
			expectedResult: scopeFlag{
				full:              "filterName=v",
				scopeName:         "filterName",
				operator:          "=",
				values:            "v",
				operatorAndValues: "=v",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName!=v",
			expectedResult: scopeFlag{
				full:              "filterName!=v",
				scopeName:         "filterName",
				operator:          "!=",
				values:            "v",
				operatorAndValues: "!=v",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName>v",
			expectedResult: scopeFlag{
				full:              "filterName>v",
				scopeName:         "filterName",
				operator:          ">",
				values:            "v",
				operatorAndValues: ">v",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName<v",
			expectedResult: scopeFlag{
				full:              "filterName<v",
				scopeName:         "filterName",
				operator:          "<",
				values:            "v",
				operatorAndValues: "<v",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName>=v",
			expectedResult: scopeFlag{
				full:              "filterName>=v",
				scopeName:         "filterName",
				operator:          ">=",
				values:            "v",
				operatorAndValues: ">=v",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName<=v",
			expectedResult: scopeFlag{
				full:              "filterName<=v",
				scopeName:         "filterName",
				operator:          "<=",
				values:            "v",
				operatorAndValues: "<=v",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName=value",
			expectedResult: scopeFlag{
				full:              "filterName=value",
				scopeName:         "filterName",
				operator:          "=",
				values:            "value",
				operatorAndValues: "=value",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName!=value",
			expectedResult: scopeFlag{
				full:              "filterName!=value",
				scopeName:         "filterName",
				operator:          "!=",
				values:            "value",
				operatorAndValues: "!=value",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName>value",
			expectedResult: scopeFlag{
				full:              "filterName>value",
				scopeName:         "filterName",
				operator:          ">",
				values:            "value",
				operatorAndValues: ">value",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName<value",
			expectedResult: scopeFlag{
				full:              "filterName<value",
				scopeName:         "filterName",
				operator:          "<",
				values:            "value",
				operatorAndValues: "<value",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName>=value",
			expectedResult: scopeFlag{
				full:              "filterName>=value",
				scopeName:         "filterName",
				operator:          ">=",
				values:            "value",
				operatorAndValues: ">=value",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName<=value",
			expectedResult: scopeFlag{
				full:              "filterName<=value",
				scopeName:         "filterName",
				operator:          "<=",
				values:            "value",
				operatorAndValues: "<=value",
			},
			expectedError: nil,
		},

		// Invalid
		// InvalidFlagEmpty
		{
			name:           "InvalidFlagEmpty",
			flag:           "",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFlagEmpty(),
		},
		// InvalidFilterFlagFormat
		{
			name:           "InvalidFilterFlagFormat",
			flag:           "filterName=",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFilterFlagFormat("filterName="),
		},
		{
			name:           "InvalidFilterFlagFormat",
			flag:           "filterName!=",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFilterFlagFormat("filterName!="),
		},
		{
			name:           "InvalidFilterFlagFormat",
			flag:           "filterName<",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFilterFlagFormat("filterName<"),
		},
		{
			name:           "InvalidFilterFlagFormat",
			flag:           "filterName>",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFilterFlagFormat("filterName>"),
		},
		{
			name:           "InvalidFilterFlagFormat",
			flag:           "filterName>=",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFilterFlagFormat("filterName>="),
		},
		{
			name:           "InvalidFilterFlagFormat",
			flag:           "filterName<=",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFilterFlagFormat("filterName<="),
		},
		// InvalidFlagOperator
		{
			name:           "InvalidFlagOperator",
			flag:           "filterName==value",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFlagOperator("filterName==value"),
		},
		{
			name:           "InvalidFlagOperator",
			flag:           "filterName=!value",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFlagOperator("filterName=!value"),
		},
		{
			name:           "InvalidFlagOperator",
			flag:           "filterName!!value",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFlagOperator("filterName!!value"),
		},
		{
			name:           "InvalidFlagOperator",
			flag:           "filterName>>value",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFlagOperator("filterName>>value"),
		},
		{
			name:           "InvalidFlagOperator",
			flag:           "filterName<>value",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFlagOperator("filterName<>value"),
		},
		{
			name:           "InvalidFlagOperator",
			flag:           "filterName>!value",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFlagOperator("filterName>!value"),
		},
		{
			name:           "InvalidFlagOperator",
			flag:           "filterName!<value",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFlagOperator("filterName!<value"),
		},
		// InvalidFlagValue
		{
			name:           "InvalidFlagValue",
			flag:           "filterName< value",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFlagValue("filterName< value"),
		},
		{
			name:           "InvalidFlagValue",
			flag:           "filterName>=value ",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFlagValue("filterName>=value "),
		},
		{
			name:           "InvalidFlagValue",
			flag:           "filterName=\tvalue",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFlagValue("filterName=\tvalue"),
		},
		{
			name:           "InvalidFlagValue",
			flag:           "filterName=value\t",
			expectedResult: scopeFlag{},
			expectedError:  InvalidFlagValue("filterName=value\t"),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseScopeFlag(tt.flag)
			if err != nil {
				require.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

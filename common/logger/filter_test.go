package logger

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterKind(t *testing.T) {
	assert.Equal(t, FilterKind(0), FilterIn)
	assert.Equal(t, FilterKind(1), FilterOut)
}

func TestNewLoggerFilter(t *testing.T) {
	filter := NewLoggerFilter()

	assert.NotNil(t, filter.msg)
	assert.NotNil(t, filter.pkg)
	assert.NotNil(t, filter.file)
	assert.NotNil(t, filter.lvl)
	assert.NotNil(t, filter.msgRegex)
	assert.False(t, filter.filterInEnabled)
	assert.False(t, filter.filterOutEnabled)
	assert.False(t, filter.Enabled())
}

func TestLoggerFilter_AddMsg(t *testing.T) {
	filter := NewLoggerFilter()

	// Test adding filter-in
	err := filter.AddMsg("test", FilterIn)
	assert.NoError(t, err)
	assert.True(t, filter.filterInEnabled)
	assert.True(t, filter.Enabled())

	// Test adding filter-out for same key should succeed (filter-out has precedence)
	err = filter.AddMsg("test", FilterOut)
	assert.NoError(t, err)
	assert.True(t, filter.filterOutEnabled)

	// Test adding filter-in for key that already has filter-out should fail
	err = filter.AddMsg("test", FilterIn)
	assert.ErrorIs(t, err, ErrFilterOutExistsForKey)

	// Test adding different key
	err = filter.AddMsg("other", FilterIn)
	assert.NoError(t, err)
}

func TestLoggerFilter_AddPkg(t *testing.T) {
	filter := NewLoggerFilter()

	err := filter.AddPkg("package", FilterIn)
	assert.NoError(t, err)
	assert.True(t, filter.filterInEnabled)

	err = filter.AddPkg("package", FilterOut)
	assert.NoError(t, err)
	assert.True(t, filter.filterOutEnabled)

	err = filter.AddPkg("package", FilterIn)
	assert.ErrorIs(t, err, ErrFilterOutExistsForKey)
}

func TestLoggerFilter_AddFile(t *testing.T) {
	filter := NewLoggerFilter()

	err := filter.AddFile("file.go", FilterIn)
	assert.NoError(t, err)
	assert.True(t, filter.filterInEnabled)

	err = filter.AddFile("file.go", FilterOut)
	assert.NoError(t, err)
	assert.True(t, filter.filterOutEnabled)

	err = filter.AddFile("file.go", FilterIn)
	assert.ErrorIs(t, err, ErrFilterOutExistsForKey)
}

func TestLoggerFilter_AddLvl(t *testing.T) {
	filter := NewLoggerFilter()

	err := filter.AddLvl(int(InfoLevel), FilterIn)
	assert.NoError(t, err)
	assert.True(t, filter.filterInEnabled)

	err = filter.AddLvl(int(InfoLevel), FilterOut)
	assert.NoError(t, err)
	assert.True(t, filter.filterOutEnabled)

	err = filter.AddLvl(int(InfoLevel), FilterIn)
	assert.ErrorIs(t, err, ErrFilterOutExistsForKey)
}

func TestLoggerFilter_AddMsgRegex(t *testing.T) {
	filter := NewLoggerFilter()

	// Test valid regex
	err := filter.AddMsgRegex("test.*", FilterIn)
	assert.NoError(t, err)
	assert.True(t, filter.filterInEnabled)

	// Test invalid regex
	err = filter.AddMsgRegex("[", FilterIn)
	assert.Error(t, err)

	// Test adding filter-out for same pattern
	err = filter.AddMsgRegex("test.*", FilterOut)
	assert.NoError(t, err)
	assert.True(t, filter.filterOutEnabled)

	// Test adding filter-in for pattern that already has filter-out should fail
	err = filter.AddMsgRegex("test.*", FilterIn)
	assert.ErrorIs(t, err, ErrFilterOutExistsForKey)
}

func TestFilterString(t *testing.T) {
	fs := newFilterString()
	assert.NotNil(t, fs.vals)
	assert.False(t, fs.enabled())

	// Test adding filter-in
	err := fs.add("test", FilterIn)
	assert.NoError(t, err)
	assert.True(t, fs.enabled())
	assert.True(t, fs.filterIn("test"))
	assert.False(t, fs.filterOut("test"))
	assert.False(t, fs.filterIn("other"))
	assert.False(t, fs.filterOut("other"))

	// Test adding filter-out for same key (should succeed, has precedence)
	err = fs.add("test", FilterOut)
	assert.NoError(t, err)
	assert.False(t, fs.filterIn("test"))
	assert.True(t, fs.filterOut("test"))

	// Test adding filter-in for key that already exists should fail
	err = fs.add("test", FilterIn)
	assert.ErrorIs(t, err, ErrFilterOutExistsForKey)

	// Test adding different key
	err = fs.add("other", FilterIn)
	assert.NoError(t, err)
	assert.True(t, fs.filterIn("other"))
}

func TestFilterStringContains(t *testing.T) {
	fsc := newFilterStringContains()
	assert.NotNil(t, fsc.vals)
	assert.False(t, fsc.enabled())

	// Test adding filter-in
	err := fsc.add("test", FilterIn)
	assert.NoError(t, err)
	assert.True(t, fsc.enabled())
	assert.True(t, fsc.filterIn("this is a test message"))
	assert.False(t, fsc.filterOut("this is a test message"))
	assert.False(t, fsc.filterIn("this is a message"))
	assert.False(t, fsc.filterOut("this is a message"))

	// Test adding filter-out for same key
	err = fsc.add("test", FilterOut)
	assert.NoError(t, err)
	assert.False(t, fsc.filterIn("this is a test message"))
	assert.True(t, fsc.filterOut("this is a test message"))

	// Test adding filter-in for key that already exists should fail
	err = fsc.add("test", FilterIn)
	assert.ErrorIs(t, err, ErrFilterOutExistsForKey)

	// Test multiple keys
	err = fsc.add("error", FilterIn)
	assert.NoError(t, err)
	assert.True(t, fsc.filterIn("error occurred"))
	assert.False(t, fsc.filterIn("warning occurred"))

	// Test multiple matches
	err = fsc.add("another", FilterOut)
	assert.NoError(t, err)
	assert.True(t, fsc.filterOut("test another message")) // Should match both "test" (FilterOut) and "another" (FilterOut)
	assert.True(t, fsc.filterOut("another test message")) // Should match both
}

func TestFilterStringRegex(t *testing.T) {
	fsr := newFilterStringRegex()
	assert.NotNil(t, fsr.vals)
	assert.False(t, fsr.enabled())

	// Test adding valid regex
	err := fsr.add("test.*", FilterIn)
	assert.NoError(t, err)
	assert.True(t, fsr.enabled())
	assert.True(t, fsr.filterIn("test message"))
	assert.True(t, fsr.filterIn("testing"))
	assert.False(t, fsr.filterOut("test message"))
	assert.False(t, fsr.filterIn("other message"))

	// Test adding invalid regex
	err = fsr.add("[", FilterIn)
	assert.Error(t, err)

	// Test adding filter-out for same pattern
	err = fsr.add("test.*", FilterOut)
	assert.NoError(t, err)
	assert.False(t, fsr.filterIn("test message"))
	assert.True(t, fsr.filterOut("test message"))

	// Test adding filter-in for pattern that already exists should fail
	err = fsr.add("test.*", FilterIn)
	assert.ErrorIs(t, err, ErrFilterOutExistsForKey)

	// Test multiple patterns
	err = fsr.add("error\\d+", FilterIn)
	assert.NoError(t, err)
	assert.True(t, fsr.filterIn("error123"))
	assert.False(t, fsr.filterIn("error"))

	// Test regex compilation
	_, ok := fsr.vals["test.*"]
	assert.True(t, ok)
	assert.NotNil(t, fsr.vals["test.*"].r)
}

func TestFilterInt(t *testing.T) {
	fi := newFilterInt()
	assert.NotNil(t, fi.vals)
	assert.False(t, fi.enabled())

	// Test adding filter-in
	err := fi.add(1, FilterIn)
	assert.NoError(t, err)
	assert.True(t, fi.enabled())
	assert.True(t, fi.filterIn(1))
	assert.False(t, fi.filterOut(1))
	assert.False(t, fi.filterIn(2))
	assert.False(t, fi.filterOut(2))

	// Test adding filter-out for same value
	err = fi.add(1, FilterOut)
	assert.NoError(t, err)
	assert.False(t, fi.filterIn(1))
	assert.True(t, fi.filterOut(1))

	// Test adding filter-in for value that already exists should fail
	err = fi.add(1, FilterIn)
	assert.ErrorIs(t, err, ErrFilterOutExistsForKey)

	// Test adding different value
	err = fi.add(2, FilterIn)
	assert.NoError(t, err)
	assert.True(t, fi.filterIn(2))
}

func TestFilterHelperFunctions(t *testing.T) {
	// Save original state
	originalLogger := pkgLogger.l
	originalCfg := pkgLogger.cfg
	defer func() {
		pkgLogger.l = originalLogger
		pkgLogger.cfg = originalCfg
	}()

	// Setup test logger with filters
	mock := newMockLogger()
	cfg := NewDefaultLoggingConfig()
	cfg.Logger = mock

	// Add some filters
	cfg.Filter.AddMsg("filtered", FilterOut)
	cfg.Filter.AddPkg("testpkg", FilterOut)
	cfg.Filter.AddFile("test.go", FilterOut)
	cfg.Filter.AddLvl(int(ErrorLevel), FilterOut)
	cfg.Filter.AddMsgRegex("error.*", FilterOut)

	Init(cfg)

	ci := &callerInfo{
		pkg:  "testpkg",
		file: "test.go",
		line: 10,
	}

	// Test filterOut function
	tests := []struct {
		name     string
		msg      string
		level    Level
		ci       *callerInfo
		expected bool
	}{
		{
			name:     "filter by message",
			msg:      "filtered message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "other", file: "other.go"},
			expected: true,
		},
		{
			name:     "filter by package",
			msg:      "normal message",
			level:    InfoLevel,
			ci:       ci,
			expected: true,
		},
		{
			name:     "filter by file",
			msg:      "normal message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "other", file: "test.go"},
			expected: true,
		},
		{
			name:     "filter by level",
			msg:      "normal message",
			level:    ErrorLevel,
			ci:       &callerInfo{pkg: "other", file: "other.go"},
			expected: true,
		},
		{
			name:     "filter by regex",
			msg:      "error occurred",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "other", file: "other.go"},
			expected: true,
		},
		{
			name:     "no filter match",
			msg:      "normal message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "other", file: "other.go"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterOut(tt.msg, tt.level, tt.ci)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFilterInHelperFunction(t *testing.T) {
	// Save original state
	originalLogger := pkgLogger.l
	originalCfg := pkgLogger.cfg
	defer func() {
		pkgLogger.l = originalLogger
		pkgLogger.cfg = originalCfg
	}()

	// Setup test logger with FilterIn filters
	mock := newMockLogger()
	cfg := NewDefaultLoggingConfig()
	cfg.Logger = mock

	// Add FilterIn filters
	cfg.Filter.AddMsg("allowed", FilterIn)
	cfg.Filter.AddPkg("allowedpkg", FilterIn)
	cfg.Filter.AddFile("allowed.go", FilterIn)
	cfg.Filter.AddLvl(int(InfoLevel), FilterIn)
	cfg.Filter.AddMsgRegex("info.*", FilterIn)

	Init(cfg)

	tests := []struct {
		name     string
		msg      string
		level    Level
		ci       *callerInfo
		expected bool
	}{
		{
			name:     "all filters match",
			msg:      "allowed info message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "allowedpkg", file: "allowed.go"},
			expected: true,
		},
		{
			name:     "message filter fails",
			msg:      "blocked message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "allowedpkg", file: "allowed.go"},
			expected: false,
		},
		{
			name:     "package filter fails",
			msg:      "allowed info message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "blockedpkg", file: "allowed.go"},
			expected: false,
		},
		{
			name:     "file filter fails",
			msg:      "allowed info message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "allowedpkg", file: "blocked.go"},
			expected: false,
		},
		{
			name:     "level filter fails",
			msg:      "allowed info message",
			level:    ErrorLevel,
			ci:       &callerInfo{pkg: "allowedpkg", file: "allowed.go"},
			expected: false,
		},
		{
			name:     "regex filter fails",
			msg:      "allowed error message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "allowedpkg", file: "allowed.go"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterIn(tt.msg, tt.level, tt.ci)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShouldOutput(t *testing.T) {
	// Save original state
	originalLogger := pkgLogger.l
	originalCfg := pkgLogger.cfg
	defer func() {
		pkgLogger.l = originalLogger
		pkgLogger.cfg = originalCfg
	}()

	tests := []struct {
		name        string
		setupFilter func(*LoggingConfig)
		msg         string
		level       Level
		ci          *callerInfo
		expected    bool
	}{
		{
			name:        "no filters enabled",
			setupFilter: func(cfg *LoggingConfig) {},
			msg:         "any message",
			level:       InfoLevel,
			ci:          &callerInfo{pkg: "any", file: "any.go"},
			expected:    true,
		},
		{
			name: "filter out enabled and matches",
			setupFilter: func(cfg *LoggingConfig) {
				cfg.Filter.AddMsg("blocked", FilterOut)
			},
			msg:      "blocked message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "any", file: "any.go"},
			expected: false,
		},
		{
			name: "filter out enabled but doesn't match",
			setupFilter: func(cfg *LoggingConfig) {
				cfg.Filter.AddMsg("blocked", FilterOut)
			},
			msg:      "allowed message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "any", file: "any.go"},
			expected: true,
		},
		{
			name: "filter in enabled and matches",
			setupFilter: func(cfg *LoggingConfig) {
				cfg.Filter.AddMsg("allowed", FilterIn)
			},
			msg:      "allowed message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "any", file: "any.go"},
			expected: true,
		},
		{
			name: "filter in enabled but doesn't match",
			setupFilter: func(cfg *LoggingConfig) {
				cfg.Filter.AddMsg("allowed", FilterIn)
			},
			msg:      "blocked message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "any", file: "any.go"},
			expected: false,
		},
		{
			name: "both filters enabled, filter out takes precedence",
			setupFilter: func(cfg *LoggingConfig) {
				cfg.Filter.AddMsg("test", FilterIn)
				cfg.Filter.AddMsg("blocked", FilterOut)
			},
			msg:      "blocked message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "any", file: "any.go"},
			expected: false,
		},
		{
			name: "both filters enabled, filter in allows",
			setupFilter: func(cfg *LoggingConfig) {
				cfg.Filter.AddMsg("allowed", FilterIn)
				cfg.Filter.AddMsg("blocked", FilterOut)
			},
			msg:      "allowed message",
			level:    InfoLevel,
			ci:       &callerInfo{pkg: "any", file: "any.go"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockLogger()
			cfg := NewDefaultLoggingConfig()
			cfg.Logger = mock
			tt.setupFilter(&cfg)
			Init(cfg)

			result := shouldOutput(tt.msg, tt.level, tt.ci)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRegexValStruct(t *testing.T) {
	regex, err := regexp.Compile("test.*")
	require.NoError(t, err)

	rv := regexVal{
		r: regex,
		t: FilterIn,
	}

	assert.NotNil(t, rv.r)
	assert.Equal(t, FilterIn, rv.t)
	assert.True(t, rv.r.MatchString("test message"))
	assert.False(t, rv.r.MatchString("other message"))
}

func TestErrFilterOutExistsForKey(t *testing.T) {
	assert.NotNil(t, ErrFilterOutExistsForKey)
	assert.Equal(t, "filter-out key already exists in filter", ErrFilterOutExistsForKey.Error())
}

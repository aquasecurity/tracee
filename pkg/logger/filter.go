package logger

import (
	"errors"
	"regexp"
	"strings"
)

// FilterKind is used to specify whether a filter should be applied to
// logs that match the filter or logs that do not match the filter.
type FilterKind int

// FilterKind values
const (
	FilterIn FilterKind = iota
	FilterOut
)

// ErrFilterOutExistsForKey must be returned when a filter-out already exists for a given key.
var ErrFilterOutExistsForKey = errors.New("filter-out key already exists in filter")

// LoggerFilter is used to filter logs.
type LoggerFilter struct {
	msg              *filterStringContains
	pkg              *filterString
	file             *filterString
	lvl              *filterInt
	msgRegex         *filterStringRegex
	filterInEnabled  bool
	filterOutEnabled bool
}

// NewLoggerFilter creates a new LoggerFilter.
func NewLoggerFilter() LoggerFilter {
	return LoggerFilter{
		msg:              newFilterStringContains(),
		pkg:              newFilterString(),
		file:             newFilterString(),
		lvl:              newFilterInt(),
		msgRegex:         newFilterStringRegex(),
		filterInEnabled:  false,
		filterOutEnabled: false,
	}
}

// AddMsg adds a filter value and type to be checked against messages.
func (lf *LoggerFilter) AddMsg(s string, t FilterKind) error {
	lf.setFilterEnabled(t)
	return lf.msg.add(s, t)
}

// AddPkg adds a filter value and type to be checked against package names.
func (lf *LoggerFilter) AddPkg(s string, t FilterKind) error {
	lf.setFilterEnabled(t)
	return lf.pkg.add(s, t)
}

// AddFile adds a filter value and type to be checked against file names.
func (lf *LoggerFilter) AddFile(s string, t FilterKind) error {
	lf.setFilterEnabled(t)
	return lf.file.add(s, t)
}

// AddLvl adds a filter value and type to be checked against log levels.
func (lf *LoggerFilter) AddLvl(i int, t FilterKind) error {
	lf.setFilterEnabled(t)
	return lf.lvl.add(i, t)
}

// AddMsgRegex adds a filter regex and type to be checked against messages.
func (lf *LoggerFilter) AddMsgRegex(regex string, t FilterKind) error {
	if err := lf.msgRegex.add(regex, t); err != nil {
		return err
	}
	lf.setFilterEnabled(t)

	return nil
}

// Enabled returns true if any filters are enabled.
func (lf *LoggerFilter) Enabled() bool {
	return lf.filterInEnabled || lf.filterOutEnabled
}

// setFilterEnabled sets the filter enabled flag for the given filter type.
func (lf *LoggerFilter) setFilterEnabled(t FilterKind) {
	if t == FilterIn {
		lf.filterInEnabled = true
	} else {
		lf.filterOutEnabled = true
	}
}

// filterString

type filterString struct {
	vals map[string]FilterKind
}

func newFilterString() *filterString {
	return &filterString{
		vals: map[string]FilterKind{},
	}
}

func (fs *filterString) add(s string, t FilterKind) error {
	// filter-out has precedence over filter-in
	if _, ok := fs.vals[s]; ok && t == FilterIn {
		return ErrFilterOutExistsForKey
	}
	fs.vals[s] = t

	return nil
}

func (fs *filterString) filterOut(s string) bool {
	if t, ok := fs.vals[s]; ok {
		return t == FilterOut
	}

	return false
}

func (fs *filterString) filterIn(s string) bool {
	if t, ok := fs.vals[s]; ok {
		return t == FilterIn
	}

	return false
}

func (fs *filterString) enabled() bool {
	return len(fs.vals) > 0
}

// filterStringContains

type filterStringContains struct {
	vals map[string]FilterKind
}

func newFilterStringContains() *filterStringContains {
	return &filterStringContains{
		vals: map[string]FilterKind{},
	}
}

func (fsc *filterStringContains) add(s string, t FilterKind) error {
	// filter-out has precedence over filter-in
	if _, ok := fsc.vals[s]; ok && t == FilterIn {
		return ErrFilterOutExistsForKey
	}
	fsc.vals[s] = t

	return nil
}

func (fsc *filterStringContains) filterOut(s string) bool {
	for v, t := range fsc.vals {
		if t == FilterOut && strings.Contains(s, v) {
			return true
		}
	}

	return false
}

func (fsc *filterStringContains) filterIn(s string) bool {
	for v, t := range fsc.vals {
		if t == FilterIn && strings.Contains(s, v) {
			return true
		}
	}

	return false
}

func (fsc *filterStringContains) enabled() bool {
	return len(fsc.vals) > 0
}

// filterStringRegex

type regexVal struct {
	r *regexp.Regexp
	t FilterKind
}

type filterStringRegex struct {
	vals map[string]regexVal
}

func newFilterStringRegex() *filterStringRegex {
	return &filterStringRegex{
		vals: map[string]regexVal{},
	}
}

func (fsr *filterStringRegex) add(s string, t FilterKind) error {
	// filter-out has precedence over filter-in
	if _, ok := fsr.vals[s]; ok && t == FilterIn {
		return ErrFilterOutExistsForKey
	}

	r, err := regexp.Compile(s)
	if err != nil {
		return err
	}

	fsr.vals[s] = regexVal{
		r: r,
		t: t,
	}

	return nil
}

func (fsr *filterStringRegex) filterOut(s string) bool {
	for _, rv := range fsr.vals {
		if rv.t == FilterOut && rv.r.MatchString(s) {
			return true
		}
	}

	return false
}

func (fsr *filterStringRegex) filterIn(s string) bool {
	for _, rv := range fsr.vals {
		if rv.t == FilterIn && rv.r.MatchString(s) {
			return true
		}
	}

	return false
}

func (fsr *filterStringRegex) enabled() bool {
	return len(fsr.vals) > 0
}

// filterInt

type filterInt struct {
	vals map[int]FilterKind
}

func newFilterInt() *filterInt {
	return &filterInt{
		vals: map[int]FilterKind{},
	}
}

func (fi *filterInt) add(i int, t FilterKind) error {
	// filter-out has precedence over filter-in
	if _, ok := fi.vals[i]; ok && t == FilterIn {
		return ErrFilterOutExistsForKey
	}
	fi.vals[i] = t

	return nil
}

func (fi *filterInt) filterOut(i int) bool {
	if t, ok := fi.vals[i]; ok {
		return t == FilterOut
	}

	return false
}

func (fi *filterInt) filterIn(i int) bool {
	if t, ok := fi.vals[i]; ok {
		return t == FilterIn
	}

	return false
}

func (fi *filterInt) enabled() bool {
	return len(fi.vals) > 0
}

// filter helper functions

func filterOut(msg string, lvl Level, ci *callerInfo) bool {
	if pkgLogger.cfg.Filter.msg.enabled() && pkgLogger.cfg.Filter.msg.filterOut(msg) {
		return true
	}

	if pkgLogger.cfg.Filter.pkg.enabled() && pkgLogger.cfg.Filter.pkg.filterOut(ci.pkg) {
		return true
	}

	if pkgLogger.cfg.Filter.file.enabled() && pkgLogger.cfg.Filter.file.filterOut(ci.file) {
		return true
	}

	if pkgLogger.cfg.Filter.lvl.enabled() && pkgLogger.cfg.Filter.lvl.filterOut(int(lvl)) {
		return true
	}

	if pkgLogger.cfg.Filter.msgRegex.enabled() && pkgLogger.cfg.Filter.msgRegex.filterOut(msg) {
		return true
	}

	return false
}

func filterIn(msg string, lvl Level, ci *callerInfo) bool {
	if pkgLogger.cfg.Filter.msg.enabled() && !pkgLogger.cfg.Filter.msg.filterIn(msg) {
		return false
	}

	if pkgLogger.cfg.Filter.pkg.enabled() && !pkgLogger.cfg.Filter.pkg.filterIn(ci.pkg) {
		return false
	}

	if pkgLogger.cfg.Filter.file.enabled() && !pkgLogger.cfg.Filter.file.filterIn(ci.file) {
		return false
	}

	if pkgLogger.cfg.Filter.lvl.enabled() && !pkgLogger.cfg.Filter.lvl.filterIn(int(lvl)) {
		return false
	}

	if pkgLogger.cfg.Filter.msgRegex.enabled() && !pkgLogger.cfg.Filter.msgRegex.filterIn(msg) {
		return false
	}

	return true
}

func shouldOutput(msg string, lvl Level, ci *callerInfo) bool {
	if !pkgLogger.cfg.Filter.Enabled() {
		return true
	}

	if pkgLogger.cfg.Filter.filterOutEnabled && filterOut(msg, lvl, ci) {
		return false
	}

	if pkgLogger.cfg.Filter.filterInEnabled && !filterIn(msg, lvl, ci) {
		return false
	}

	return true
}

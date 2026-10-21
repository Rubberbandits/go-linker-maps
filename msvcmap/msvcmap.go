// Package msvcmap parses MSVC linker MAP files.
//
// Addresses produced by this package are RVAs (virtual address minus the
// preferred load address), suitable for in-memory addressing rather than for
// patching the file on disk.
package msvcmap

import (
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"
)

const (
	// hashSeed is the 'LUTL' constant that seeds and finalizes LUHash.
	hashSeed uint32 = 0x4c55544c

	baseMarker    = "Preferred load address is "
	publicsMarker = "Publics by Value"

	// minSymbolFields is the number of fields (section:offset, name, address)
	// a symbol line needs.
	minSymbolFields = 3
	hexBase         = 16
	addressBits     = 64
	// sectionParts is the number of parts in a "section:offset" field.
	sectionParts = 2
)

// ErrNoBase is returned by ParseAll when no valid "Preferred load address"
// line is present.
var ErrNoBase = errors.New("map has no preferred load address")

//nolint:gochecknoglobals // Immutable CRC32C table reused for all symbol hashes.
var luHashTable = crc32.MakeTable(crc32.Castagnoli)

// Symbol holds one parsed entry from the "Publics by Value" section.
type Symbol struct {
	// Section is the section index, for example "0001".
	Section string
	// Offset is the offset within the section.
	Offset uint64
	// Name is the full decorated name as written in the MAP file.
	Name string
	// RVA is the symbol address minus the preferred load address.
	RVA uint64
}

// LUHash computes the CRC32C-based hash used for MSVC symbol matching. This is
// the LibUtil_LUHash2 algorithm: raw CRC32C seeded and finalized with the C
// constant 'LUTL' (0x4c55544c).
func LUHash(data []byte) uint64 {
	return uint64(^crc32.Update(^hashSeed, luHashTable, data) ^ hashSeed)
}

// FindSymbol searches the MSVC MAP data for the first symbol whose name, after
// removing leading '?' decoration and truncating to nameSize bytes, hashes to
// nameHash with LUHash. It returns the symbol's RVA, or 0 when no symbol
// matches, the input is malformed, or nameSize is 0. A matching symbol whose
// address lies below the load address also yields 0.
func FindSymbol(mapData []byte, nameHash, nameSize uint64) uint64 {
	var (
		base              uint64
		haveBase, symbols bool
	)

	for line := range bytes.Lines(mapData) {
		text := string(line)

		if _, value, ok := strings.Cut(text, baseMarker); ok {
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), hexBase, addressBits)
			if err != nil {
				return 0
			}

			base, haveBase = parsed, true

			continue
		}

		if strings.Contains(text, publicsMarker) {
			symbols = haveBase

			continue
		}

		if !symbols || nameSize == 0 {
			continue
		}

		rva, found, stop := matchSymbol(text, nameHash, nameSize, base)
		if found {
			return rva
		}

		if stop {
			return 0
		}
	}

	return 0
}

// matchSymbol tests one candidate symbol line against the target name hash. It
// returns the resolved RVA, whether the line matched and yielded a valid RVA,
// and whether the search should stop. The stop flag is set when the name
// matched but the address is malformed or below the load address, in which case
// the search ends with no result.
func matchSymbol(text string, nameHash, nameSize, base uint64) (uint64, bool, bool) {
	fields, ok := symbolFields(text)
	if !ok {
		return 0, false, false
	}

	name := strings.TrimLeft(fields[1], "?")
	if nameSize > uint64(len(name)) || LUHash([]byte(name[:nameSize])) != nameHash {
		return 0, false, false
	}

	address, err := strconv.ParseUint(fields[2], hexBase, addressBits)
	if err != nil || address < base {
		return 0, false, true
	}

	return address - base, true, false
}

// ParseAll reads every symbol from the "Publics by Value" section of the MSVC
// MAP data. It returns the symbols in file order together with the preferred
// load address. Malformed symbol lines and symbols below the load address are
// skipped. ErrNoBase is returned when the MAP has no valid preferred load
// address.
func ParseAll(mapData []byte) ([]Symbol, uint64, error) {
	var (
		base              uint64
		haveBase, symbols bool
		result            []Symbol
	)

	for line := range bytes.Lines(mapData) {
		text := string(line)

		if _, value, ok := strings.Cut(text, baseMarker); ok {
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), hexBase, addressBits)
			if err != nil {
				return nil, 0, fmt.Errorf(
					"parse preferred load address %q: %w",
					strings.TrimSpace(value),
					err,
				)
			}

			base, haveBase = parsed, true

			continue
		}

		if strings.Contains(text, publicsMarker) {
			symbols = haveBase

			continue
		}

		if !symbols {
			continue
		}

		symbol, ok := parseSymbol(text, base)
		if ok {
			result = append(result, symbol)
		}
	}

	if !haveBase {
		return nil, 0, ErrNoBase
	}

	return result, base, nil
}

// symbolFields splits a candidate symbol line, reporting false when it does not
// have the "section:offset name address ..." shape.
func symbolFields(text string) ([]string, bool) {
	fields := strings.Fields(text)
	if len(fields) < minSymbolFields || !strings.Contains(fields[0], ":") {
		return nil, false
	}

	return fields, true
}

// parseSymbol converts one symbol line into a Symbol.
func parseSymbol(text string, base uint64) (Symbol, bool) {
	fields, ok := symbolFields(text)
	if !ok {
		return Symbol{}, false
	}

	section, offsetText, _ := strings.Cut(fields[0], ":")
	if section == "" || len(strings.SplitN(fields[0], ":", sectionParts)) != sectionParts {
		return Symbol{}, false
	}

	offset, err := strconv.ParseUint(offsetText, hexBase, addressBits)
	if err != nil {
		return Symbol{}, false
	}

	address, err := strconv.ParseUint(fields[2], hexBase, addressBits)
	if err != nil || address < base {
		return Symbol{}, false
	}

	return Symbol{Section: section, Offset: offset, Name: fields[1], RVA: address - base}, true
}

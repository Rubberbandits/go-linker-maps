// Package gnumap resolves symbol file offsets from GNU ld linker MAP files.
//
// Offsets produced by this package are file offsets within the PE image
// (not RVAs): they are suitable for patching the binary on disk.
package gnumap

import (
	"bufio"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Rubberbandits/go-linker-maps/peutil"
)

const (
	// symbolLinePrefix marks the MAP file lines that carry a symbol address.
	symbolLinePrefix = "                0x0"
	// headerMarker identifies the line after which symbols are collected.
	headerMarker = "SIZEOF_HEADERS"
	// minSymbolFields is the number of fields (address and name) a symbol line needs.
	minSymbolFields = 2
	// hexPrefixLen is the length of the "0x" prefix on addresses.
	hexPrefixLen = 2
	// hexBase is the numeric base of MAP addresses.
	hexBase = 16
	// addressBits is the bit size of parsed addresses.
	addressBits = 64
)

// ErrNotPE64 is returned when the binary lacks a PE32+ optional header.
var ErrNotPE64 = errors.New("binary does not have a PE32+ optional header")

// Symbol holds one resolved symbol from a GNU MAP file.
type Symbol struct {
	// Name is the symbol name as written in the MAP file.
	Name string
	// Address is the virtual address from the MAP line.
	Address uint64
	// FileOffset is the computed file offset in the PE image.
	FileOffset uint64
}

// ParseFile reads the GNU ld MAP file at mapPath and resolves every symbol's
// file offset against the PE image at binaryPath. It returns a map from symbol
// name to file offset. When a name appears more than once, the last
// occurrence wins.
func ParseFile(mapPath, binaryPath string) (map[string]uint64, error) {
	//nolint:gosec // G304: mapPath is chosen by the caller by design
	mapf, err := os.Open(mapPath)
	if err != nil {
		return nil, fmt.Errorf("open map file: %w", err)
	}

	defer func() { _ = mapf.Close() }()

	exef, err := pe.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("open PE binary: %w", err)
	}

	defer func() { _ = exef.Close() }()

	header, ok := exef.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return nil, ErrNotPE64
	}

	symbols, err := Parse(mapf, peutil.SectionsFromPE(exef), header.ImageBase)
	if err != nil {
		return nil, err
	}

	offsets := make(map[string]uint64, len(symbols))
	for _, symbol := range symbols {
		offsets[symbol.Name] = symbol.FileOffset
	}

	return offsets, nil
}

// Parse reads a GNU ld MAP from r and resolves symbol addresses against the
// given PE sections and image base. Lines before the SIZEOF_HEADERS marker are
// ignored, as are symbols whose address lies below the image base or outside
// every section.
func Parse(r io.Reader, sections []peutil.Section, imageBase uint64) ([]Symbol, error) {
	var symbols []Symbol

	scanner := bufio.NewScanner(r)
	foundHeader := false

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, symbolLinePrefix) {
			continue
		}

		if !foundHeader {
			foundHeader = strings.Contains(line, headerMarker)

			continue
		}

		symbol, found, err := parseSymbolLine(line, sections, imageBase)
		if err != nil {
			return nil, err
		}

		if found {
			symbols = append(symbols, symbol)
		}
	}

	err := scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("read map file: %w", err)
	}

	return symbols, nil
}

// parseSymbolLine parses one MAP symbol line. found is false when the line does
// not describe a symbol inside one of the image's sections.
func parseSymbolLine(
	line string,
	sections []peutil.Section,
	imageBase uint64,
) (Symbol, bool, error) {
	parts := strings.Fields(line)
	if len(parts) < minSymbolFields || !strings.Contains(parts[0], "0x") {
		return Symbol{}, false, nil
	}

	address, err := strconv.ParseUint(parts[0][hexPrefixLen:], hexBase, addressBits)
	if err != nil {
		return Symbol{}, false, fmt.Errorf("parse symbol address %q: %w", parts[0], err)
	}

	offset, ok := peutil.FileOffset(address, imageBase, sections)
	if !ok {
		return Symbol{}, false, nil
	}

	return Symbol{Name: parts[1], Address: address, FileOffset: offset}, true, nil
}

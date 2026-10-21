package gnumap_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Rubberbandits/go-linker-maps/gnumap"
	"github.com/Rubberbandits/go-linker-maps/peutil"
)

const imageBase = 0x140000000

func testSections() []peutil.Section {
	return []peutil.Section{
		{
			Name:           ".text",
			VirtualAddress: 0x1000,
			VirtualSize:    0x2000,
			Offset:         0x400,
			RawSize:        0x2000,
		},
		{
			Name:           ".data",
			VirtualAddress: 0x4000,
			VirtualSize:    0x1000,
			Offset:         0x2400,
			RawSize:        0x1000,
		},
	}
}

func symbolLine(address, name string) string {
	return "                " + address + "                " + name + "\n"
}

func TestParseSampleFile(t *testing.T) {
	t.Parallel()

	file, err := os.Open(filepath.Join("..", "testdata", "gnu_sample.map"))
	if err != nil {
		t.Fatalf("open sample: %v", err)
	}

	defer func() { _ = file.Close() }()

	symbols, err := gnumap.Parse(file, testSections(), imageBase)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := []gnumap.Symbol{
		{Name: "alpha", Address: imageBase + 0x1230, FileOffset: 0x630},
		{Name: "beta", Address: imageBase + 0x1800, FileOffset: 0xc00},
		{Name: "gamma", Address: imageBase + 0x4010, FileOffset: 0x2410},
	}

	if len(symbols) != len(want) {
		t.Fatalf("got %d symbols (%+v), want %d", len(symbols), symbols, len(want))
	}

	for i := range want {
		if symbols[i] != want[i] {
			t.Errorf("symbol %d = %+v, want %+v", i, symbols[i], want[i])
		}
	}
}

func TestParseSkipsLinesBeforeHeader(t *testing.T) {
	t.Parallel()

	input := symbolLine("0x0000000140001000", "early") +
		symbolLine("0x0000000000000400", ". = SIZEOF_HEADERS") +
		symbolLine("0x0000000140001230", "late")

	symbols, err := gnumap.Parse(strings.NewReader(input), testSections(), imageBase)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(symbols) != 1 || symbols[0].Name != "late" {
		t.Fatalf("got %+v, want only \"late\"", symbols)
	}
}

func TestParseNoHeaderYieldsNothing(t *testing.T) {
	t.Parallel()

	input := symbolLine("0x0000000140001230", "alpha")

	symbols, err := gnumap.Parse(strings.NewReader(input), testSections(), imageBase)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(symbols) != 0 {
		t.Fatalf("got %+v, want none", symbols)
	}
}

func TestParseDropsUnmappedAddresses(t *testing.T) {
	t.Parallel()

	input := symbolLine("0x0000000000000400", ". = SIZEOF_HEADERS") +
		symbolLine("0x0000000140009000", "outside") +
		symbolLine("0x0000000000001000", "below_base") +
		symbolLine("0x0000000140001230", "inside")

	symbols, err := gnumap.Parse(strings.NewReader(input), testSections(), imageBase)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(symbols) != 1 || symbols[0].Name != "inside" {
		t.Fatalf("got %+v, want only \"inside\"", symbols)
	}
}

func TestParseBadAddress(t *testing.T) {
	t.Parallel()

	input := symbolLine("0x0000000000000400", ". = SIZEOF_HEADERS") +
		symbolLine("0x0zzzzzzzzzzzzzzz", "broken")

	_, err := gnumap.Parse(strings.NewReader(input), testSections(), imageBase)
	if err == nil {
		t.Fatal("expected error for malformed address")
	}
}

func TestParseIgnoresShortLines(t *testing.T) {
	t.Parallel()

	input := symbolLine("0x0000000000000400", ". = SIZEOF_HEADERS") +
		"                0x0000000140001230\n"

	symbols, err := gnumap.Parse(strings.NewReader(input), testSections(), imageBase)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(symbols) != 0 {
		t.Fatalf("got %+v, want none", symbols)
	}
}

func TestParseEmptyInput(t *testing.T) {
	t.Parallel()

	symbols, err := gnumap.Parse(strings.NewReader(""), nil, 0)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(symbols) != 0 {
		t.Fatalf("got %+v, want none", symbols)
	}
}

func TestParseFileMissingMap(t *testing.T) {
	t.Parallel()

	_, err := gnumap.ParseFile(filepath.Join(t.TempDir(), "missing.map"), "missing.exe")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v, want os.ErrNotExist", err)
	}
}

func TestParseFileNotPE(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mapPath := filepath.Join(dir, "a.map")
	binPath := filepath.Join(dir, "a.exe")

	err := os.WriteFile(mapPath, []byte(""), 0o600)
	if err != nil {
		t.Fatalf("write map: %v", err)
	}

	err = os.WriteFile(binPath, []byte("not a PE file"), 0o600)
	if err != nil {
		t.Fatalf("write binary: %v", err)
	}

	_, err = gnumap.ParseFile(mapPath, binPath)
	if err == nil {
		t.Fatal("expected error for non-PE binary")
	}
}

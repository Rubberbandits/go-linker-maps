package msvcmap_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Rubberbandits/go-linker-maps/msvcmap"
)

const (
	refSeed uint32 = 0x4c55544c
	refPoly uint32 = 0x82f63b78
)

// referenceLUHash is an independent bitwise CRC32C implementation of LUHash.
func referenceLUHash(data []byte) uint64 {
	crc := refSeed

	for _, b := range data {
		crc ^= uint32(b)

		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ refPoly
			} else {
				crc >>= 1
			}
		}
	}

	return uint64(crc ^ refSeed)
}

func loadSample(t *testing.T) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "testdata", "msvc_sample.map"))
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	return data
}

func hashOf(name string) (uint64, uint64) {
	return msvcmap.LUHash([]byte(name)), uint64(len(name))
}

func TestLUHashEmpty(t *testing.T) {
	t.Parallel()

	if got := msvcmap.LUHash(nil); got != 0 {
		t.Fatalf("LUHash(nil) = %#x, want 0", got)
	}
}

func TestLUHashMatchesReference(t *testing.T) {
	t.Parallel()

	inputs := []string{"a", "alpha", "123456789", "hook_target", "mainCRTStartup", "\x00\xff\x10"}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			t.Parallel()

			got := msvcmap.LUHash([]byte(input))
			if want := referenceLUHash([]byte(input)); got != want {
				t.Fatalf("LUHash(%q) = %#x, want %#x", input, got, want)
			}

			if got > 0xffffffff {
				t.Fatalf("LUHash(%q) = %#x does not fit in 32 bits", input, got)
			}
		})
	}
}

func TestFindSymbol(t *testing.T) {
	t.Parallel()

	data := loadSample(t)

	tests := []struct {
		name   string
		symbol string
		size   uint64
		want   uint64
	}{
		{name: "decorated C++ name", symbol: "alpha", want: 0x1230},
		{name: "plain name", symbol: "beta_symbol", want: 0x1800},
		{name: "double question mark decoration", symbol: "gamma", want: 0x4010},
		{name: "exact full name", symbol: "delta", want: 0x4020},
		{name: "unknown symbol", symbol: "nonexistent", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hash, size := hashOf(tt.symbol)
			if got := msvcmap.FindSymbol(data, hash, size); got != tt.want {
				t.Fatalf("FindSymbol(%q) = %#x, want %#x", tt.symbol, got, tt.want)
			}
		})
	}
}

func TestFindSymbolPrefixMatch(t *testing.T) {
	t.Parallel()

	data := loadSample(t)
	hash, size := hashOf("beta")

	if got := msvcmap.FindSymbol(data, hash, size); got != 0x1800 {
		t.Fatalf("prefix lookup = %#x, want 0x1800", got)
	}
}

func TestFindSymbolDegenerateInput(t *testing.T) {
	t.Parallel()

	data := loadSample(t)
	hash, size := hashOf("alpha")

	tests := []struct {
		name string
		data []byte
		hash uint64
		size uint64
	}{
		{name: "nil data", data: nil, hash: hash, size: size},
		{name: "empty data", data: []byte{}, hash: hash, size: size},
		{name: "garbage", data: []byte("not a map file\n\x00\x01"), hash: hash, size: size},
		{name: "zero size", data: data, hash: hash, size: 0},
		{name: "size longer than name", data: data, hash: hash, size: 1000},
		{
			name: "bad base",
			data: []byte("Preferred load address is zzzz\nPublics by Value\n0001:0 alpha 1000\n"),
			hash: hash, size: size,
		},
		{
			name: "publics without base",
			data: []byte("Publics by Value\n 0001:00001230 alpha 0000000140001230\n"),
			hash: hash, size: size,
		},
		{
			name: "address below base",
			data: []byte("Preferred load address is 2000\nPublics by Value\n 0001:0 alpha 1000\n"),
			hash: hash, size: size,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := msvcmap.FindSymbol(tt.data, tt.hash, tt.size); got != 0 {
				t.Fatalf("FindSymbol = %#x, want 0", got)
			}
		})
	}
}

func TestParseAll(t *testing.T) {
	t.Parallel()

	symbols, base, err := msvcmap.ParseAll(loadSample(t))
	if err != nil {
		t.Fatalf("ParseAll: %v", err)
	}

	if base != 0x140000000 {
		t.Fatalf("base = %#x, want 0x140000000", base)
	}

	want := []msvcmap.Symbol{
		{Section: "0001", Offset: 0x1230, Name: "?alpha@@YAXXZ", RVA: 0x1230},
		{Section: "0001", Offset: 0x1800, Name: "beta_symbol", RVA: 0x1800},
		{Section: "0002", Offset: 0x10, Name: "??gamma@@3HA", RVA: 0x4010},
		{Section: "0002", Offset: 0x20, Name: "delta", RVA: 0x4020},
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

func TestParseAllAgreesWithFindSymbol(t *testing.T) {
	t.Parallel()

	data := loadSample(t)

	symbols, _, err := msvcmap.ParseAll(data)
	if err != nil {
		t.Fatalf("ParseAll: %v", err)
	}

	for _, symbol := range symbols {
		// FindSymbol hashes the name after trimming '?', so use the trimmed form.
		hash, size := hashOf(strings.TrimLeft(symbol.Name, "?"))
		if got := msvcmap.FindSymbol(data, hash, size); got != symbol.RVA {
			t.Errorf("FindSymbol(%q) = %#x, ParseAll RVA = %#x", symbol.Name, got, symbol.RVA)
		}
	}
}

func TestParseAllErrors(t *testing.T) {
	t.Parallel()

	_, _, err := msvcmap.ParseAll([]byte("Publics by Value\n 0001:0 a 10\n"))
	if !errors.Is(err, msvcmap.ErrNoBase) {
		t.Fatalf("got %v, want ErrNoBase", err)
	}

	_, _, err = msvcmap.ParseAll(nil)
	if !errors.Is(err, msvcmap.ErrNoBase) {
		t.Fatalf("nil input: got %v, want ErrNoBase", err)
	}

	_, _, err = msvcmap.ParseAll([]byte("Preferred load address is nothex\n"))
	if err == nil {
		t.Fatal("expected error for malformed base")
	}
}

func TestParseAllNoPublics(t *testing.T) {
	t.Parallel()

	symbols, base, err := msvcmap.ParseAll([]byte("Preferred load address is 10000\n"))
	if err != nil {
		t.Fatalf("ParseAll: %v", err)
	}

	if len(symbols) != 0 || base != 0x10000 {
		t.Fatalf("got (%v, %#x), want no symbols and base 0x10000", symbols, base)
	}
}

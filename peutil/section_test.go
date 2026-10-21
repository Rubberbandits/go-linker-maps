package peutil_test

import (
	"debug/pe"
	"testing"

	"github.com/Rubberbandits/go-linker-maps/peutil"
)

const (
	textSection = ".text"
	dataSection = ".data"
)

func testSections() []peutil.Section {
	return []peutil.Section{
		{
			Name:           textSection,
			VirtualAddress: 0x1000,
			VirtualSize:    0x2000,
			Offset:         0x400,
			RawSize:        0x2000,
		},
		{
			Name:           dataSection,
			VirtualAddress: 0x4000,
			VirtualSize:    0x1000,
			Offset:         0x2400,
			RawSize:        0x1000,
		},
	}
}

func TestSectionFromRVA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rva  uint32
		want string
	}{
		{name: "start of first section", rva: 0x1000, want: textSection},
		{name: "inside first section", rva: 0x1230, want: textSection},
		{name: "last byte of first section", rva: 0x2fff, want: textSection},
		{name: "end boundary is exclusive", rva: 0x3000, want: ""},
		{name: "gap between sections", rva: 0x3800, want: ""},
		{name: "second section", rva: 0x4010, want: dataSection},
		{name: "below all sections", rva: 0x10, want: ""},
		{name: "past all sections", rva: 0x9000, want: ""},
	}

	sections := testSections()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := peutil.SectionFromRVA(tt.rva, sections)
			if tt.want == "" {
				if got != nil {
					t.Fatalf("SectionFromRVA(%#x) = %q, want nil", tt.rva, got.Name)
				}

				return
			}

			if got == nil || got.Name != tt.want {
				t.Fatalf("SectionFromRVA(%#x) = %v, want %q", tt.rva, got, tt.want)
			}
		})
	}
}

func TestSectionFromRVAEmpty(t *testing.T) {
	t.Parallel()

	if got := peutil.SectionFromRVA(0x1000, nil); got != nil {
		t.Fatalf("expected nil for empty section table, got %v", got)
	}
}

func TestSectionFromRVANoOverflow(t *testing.T) {
	t.Parallel()

	sections := []peutil.Section{{Name: ".big", VirtualAddress: 0xfffffff0, VirtualSize: 0x100}}

	if got := peutil.SectionFromRVA(0xfffffff8, sections); got == nil {
		t.Fatal("expected section near the top of the address space to match")
	}
}

func TestFileOffset(t *testing.T) {
	t.Parallel()

	const imageBase = 0x140000000

	tests := []struct {
		name   string
		va     uint64
		want   uint64
		wantOK bool
	}{
		{name: "text symbol", va: imageBase + 0x1230, want: 0x630, wantOK: true},
		{name: "section start", va: imageBase + 0x1000, want: 0x400, wantOK: true},
		{name: "data symbol", va: imageBase + 0x4010, want: 0x2410, wantOK: true},
		{name: "outside sections", va: imageBase + 0x9000, wantOK: false},
		{name: "below image base", va: imageBase - 1, wantOK: false},
		{name: "rva exceeds 32 bits", va: imageBase + 0x100000000, wantOK: false},
	}

	sections := testSections()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := peutil.FileOffset(tt.va, imageBase, sections)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf(
					"FileOffset(%#x) = (%#x, %v), want (%#x, %v)",
					tt.va,
					got,
					ok,
					tt.want,
					tt.wantOK,
				)
			}
		})
	}
}

func TestSectionsFromPE(t *testing.T) {
	t.Parallel()

	file := &pe.File{
		Sections: []*pe.Section{
			{SectionHeader: pe.SectionHeader{
				Name:           textSection,
				VirtualAddress: 0x1000,
				VirtualSize:    0x2000,
				Offset:         0x400,
				Size:           0x2000,
			}},
			{SectionHeader: pe.SectionHeader{
				Name:           dataSection,
				VirtualAddress: 0x4000,
				VirtualSize:    0x1000,
				Offset:         0x2400,
				Size:           0x800,
			}},
		},
	}

	got := peutil.SectionsFromPE(file)
	if len(got) != 2 {
		t.Fatalf("got %d sections, want 2", len(got))
	}

	want := peutil.Section{
		Name:           dataSection,
		VirtualAddress: 0x4000,
		VirtualSize:    0x1000,
		Offset:         0x2400,
		RawSize:        0x800,
	}
	if got[1] != want {
		t.Fatalf("got %+v, want %+v", got[1], want)
	}
}

func TestSectionsFromPENil(t *testing.T) {
	t.Parallel()

	if got := peutil.SectionsFromPE(nil); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

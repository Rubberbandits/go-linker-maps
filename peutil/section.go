// Package peutil provides minimal PE section-table helpers used by the MAP
// parsers in this module.
package peutil

import (
	"debug/pe"
	"math"
)

// Section is a minimal representation of a PE section header, independent of
// debug/pe so callers can construct it from any source.
type Section struct {
	// Name is the section name, for example ".text".
	Name string
	// VirtualAddress is the section RVA once the image is loaded.
	VirtualAddress uint32
	// VirtualSize is the section size in memory.
	VirtualSize uint32
	// Offset is the file offset of the section data (PointerToRawData).
	Offset uint32
	// RawSize is the size of the section data on disk (SizeOfRawData).
	RawSize uint32
}

// SectionsFromPE extracts Section records from a debug/pe File.
func SectionsFromPE(f *pe.File) []Section {
	if f == nil {
		return nil
	}

	sections := make([]Section, 0, len(f.Sections))

	for _, s := range f.Sections {
		sections = append(sections, Section{
			Name:           s.Name,
			VirtualAddress: s.VirtualAddress,
			VirtualSize:    s.VirtualSize,
			Offset:         s.Offset,
			RawSize:        s.Size,
		})
	}

	return sections
}

// SectionFromRVA returns the first section whose virtual range contains rva,
// or nil when none does. The returned pointer refers into sections.
func SectionFromRVA(rva uint32, sections []Section) *Section {
	for i := range sections {
		start := uint64(sections[i].VirtualAddress)
		end := start + uint64(sections[i].VirtualSize)

		if uint64(rva) >= start && uint64(rva) < end {
			return &sections[i]
		}
	}

	return nil
}

// FileOffset converts the virtual address va to a file offset, given the image
// base and the section table. The boolean is false when va lies below the
// image base or outside every section.
func FileOffset(va, imageBase uint64, sections []Section) (uint64, bool) {
	if va < imageBase {
		return 0, false
	}

	rva := va - imageBase
	if rva > math.MaxUint32 {
		return 0, false
	}

	section := SectionFromRVA(uint32(rva), sections)
	if section == nil {
		return 0, false
	}

	return rva - uint64(section.VirtualAddress) + uint64(section.Offset), true
}

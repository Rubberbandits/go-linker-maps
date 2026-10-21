# go-linker-maps

Small, dependency-free Go packages for reading linker MAP files and the PE
section tables needed to interpret them. Released under the Unlicense.

```
go get github.com/Rubberbandits/go-linker-maps
```

## Packages

| Package   | Purpose |
|-----------|---------|
| `gnumap`  | Parses GNU ld MAP files and resolves every symbol to a **file offset** inside the PE image. |
| `msvcmap` | Parses MSVC MAP files ("Preferred load address" + "Publics by Value") and resolves symbols to **RVAs**, either by enumeration or by CRC32C name hash (`LUHash`). |
| `peutil`  | Minimal PE section-table helpers (`Section`, `SectionFromRVA`, `FileOffset`) shared by the parsers. |

The two parsers are intentionally separate: they handle different formats,
use different lookup strategies and return different kinds of offsets.

## Usage

### GNU ld MAP to file offsets

```go
offsets, err := gnumap.ParseFile("app.map", "app.exe")
if err != nil {
	log.Fatal(err)
}

fmt.Printf("placeholder at file offset %#x\n", offsets["placeholder"])
```

When the PE is already open, use the in-memory variant:

```go
f, _ := pe.Open("app.exe")
sections := peutil.SectionsFromPE(f)
symbols, err := gnumap.Parse(mapReader, sections, imageBase)
```

### MSVC MAP to RVAs

```go
data, _ := os.ReadFile("host.map")

// Enumerate everything.
symbols, base, err := msvcmap.ParseAll(data)

// Or look up one symbol by the hash of its (undecorated) name prefix.
name := []byte("hook_target")
rva := msvcmap.FindSymbol(data, msvcmap.LUHash(name), uint64(len(name)))
```

`FindSymbol` returns `0` when the symbol is not found or the input is malformed.

## Development

```
go test ./...
golangci-lint run
```

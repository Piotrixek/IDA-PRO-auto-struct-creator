# AutoStruct

Tested on IDA 9.2

AutoStruct is an IDAPython structural type inference plugin for the Hex-Rays decompiler. It automates reverse engineering workflows by auditing abstract syntax trees (AST) within decompiled functions to identify, trace, and reconstruct custom C/C++ complex memory structures and classes automatically.

## Features

- **Context-Aware Type Splitting**: Utilizes a disjoint-set (Union-Find) algorithm to map assignments accurately. It successfully isolates parent structures, nested subclasses, and separate inline pointers, preventing multiple distinct variables from merging into monolithic type groups.
- **Pointer-Aware Member Inference**: Detects inline additions, multi-dereferences, and pointer array scaling layouts, establishing proper typed pointer struct fields instead of flat generic byte buffers.
- **Automatic Alignment Normalization**: Groups individual byte modifications into natural boundary alignments (2, 4, or 8 bytes) to minimize synthetic compiler casting artifacts.
- **Topological Struct Declaration Order**: Performs a topological dependency sort across all inferred items, ensuring that nested children or referenced inline objects are registered in IDA Pro's Local Types library in the correct sequence.
- **Memory Safety Protections**: Features integrated validation guards against negative pointer offsets, compiler truncation limits, out-of-bounds calculations, and type definitions with unknown boundary constraints (BADSIZE).

## Requirements

- IDA Pro / Home (with Hex-Rays Decompiler)
- IDAPython (Python 3 environment execution)

## Installation

1. Copy the script file into your IDA Pro `plugins` directory or keep it in a dedicated scripts folder.
2. Ensure the Hex-Rays plugin dependency initializes properly within your binary analysis workspace.

## Usage

1. Open a binary inside IDA Pro and navigate to any decompiled function view window (Pseudocode-A).
2. Position your cursor anywhere inside the target function body.
3. Press `Shift-A` to execute the structural analyzer.
4. AutoStruct will extract memory fields, create the structured items, resolve typings inside the Local Types library database, and dynamically batch-apply pointer layouts directly to the pseudocode representation.

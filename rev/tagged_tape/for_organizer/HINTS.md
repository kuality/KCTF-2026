# Hints

Release these progressively.

1. **Language anchor:** The executable was produced by OCaml's native compiler. Search for how OCaml represents values in one machine word.
2. **Representation anchor:** Odd words are immediate integers. For a block pointer, inspect the word immediately before the pointed-to fields; its low byte is a tag.
3. **Extraction anchor:** A six-field record points to a 156-element array. Constructor tags 0 through 4 identify reversible operations. Start inversion with the stored target and the last operation.

open Tape_types

let marker_a = 0x13579bdf
let marker_b = 0x02468ace
let marker_c = 0x11111151
let width = 64

let read_line_exact path =
  let channel = open_in_bin path in
  Fun.protect
    ~finally:(fun () -> close_in_noerr channel)
    (fun () ->
      let length = in_channel_length channel in
      let contents = really_input_string channel length in
      let rec trim index =
        if index > 0 then
          match contents.[index - 1] with
          | '\n' | '\r' -> trim (index - 1)
          | _ -> index
        else 0
      in
      String.sub contents 0 (trim length))

let hex_value = function
  | '0' .. '9' as value -> Char.code value - Char.code '0'
  | 'a' .. 'f' as value -> Char.code value - Char.code 'a' + 10
  | 'A' .. 'F' as value -> Char.code value - Char.code 'A' + 10
  | _ -> invalid_arg "seed is not hexadecimal"

let decode_hex text =
  if String.length text mod 2 <> 0 then invalid_arg "odd seed length";
  Bytes.init (String.length text / 2) (fun index ->
      let high = hex_value text.[index * 2] in
      let low = hex_value text.[index * 2 + 1] in
      Char.chr ((high lsl 4) lor low))

let seed_state seed =
  if Bytes.length seed < 8 then invalid_arg "seed is too short";
  let state = ref 0x6a09e667f3bcc909L in
  Bytes.iteri
    (fun index value ->
      let shift = (index land 7) * 8 in
      let lane = Int64.shift_left (Int64.of_int (Char.code value)) shift in
      state := Int64.logxor !state lane;
      state :=
        Int64.add
          (Int64.mul !state 0x9e3779b97f4a7c15L)
          (Int64.of_int (index + 1)))
    seed;
  !state

type rng = { mutable state : int64 }

let next_u64 rng =
  rng.state <- Int64.add rng.state 0x9e3779b97f4a7c15L;
  let value = ref rng.state in
  value :=
    Int64.mul
      (Int64.logxor !value (Int64.shift_right_logical !value 30))
      0xbf58476d1ce4e5b9L;
  value :=
    Int64.mul
      (Int64.logxor !value (Int64.shift_right_logical !value 27))
      0x94d049bb133111ebL;
  Int64.logxor !value (Int64.shift_right_logical !value 31)

let next_int rng bound =
  if bound <= 0 then invalid_arg "non-positive random bound";
  let positive = Int64.logand (next_u64 rng) 0x7fffffffffffffffL in
  Int64.to_int (Int64.rem positive (Int64.of_int bound))

let distinct_index rng first =
  let candidate = next_int rng (width - 1) in
  if candidate >= first then candidate + 1 else candidate

let make_tape rng =
  let reversed = ref [] in
  let emit operation = reversed := operation :: !reversed in
  for index = 0 to width - 1 do
    let key = next_int rng 255 + 1 in
    match index mod 3 with
    | 0 -> emit (Xor_at (index, key))
    | 1 -> emit (Add_at (index, key))
    | _ -> emit (Rol_at (index, next_int rng 7 + 1))
  done;
  for index = 0 to (width / 2) - 1 do
    emit (Feistel (index, index + (width / 2), next_int rng 255 + 1))
  done;
  for _round = 0 to 11 do
    let index = next_int rng width in
    emit (Xor_at (index, next_int rng 255 + 1));
    let index = next_int rng width in
    emit (Add_at (index, next_int rng 255 + 1));
    let index = next_int rng width in
    emit (Rol_at (index, next_int rng 7 + 1));
    let left = next_int rng width in
    emit (Swap (left, distinct_index rng left));
    let left = next_int rng width in
    emit (Feistel (left, distinct_index rng left, next_int rng 255 + 1))
  done;
  Array.of_list (List.rev !reversed)

let output_operation channel = function
  | Xor_at (index, key) ->
      Printf.fprintf channel "    Xor_at (%d, %d);\n" index key
  | Add_at (index, key) ->
      Printf.fprintf channel "    Add_at (%d, %d);\n" index key
  | Rol_at (index, amount) ->
      Printf.fprintf channel "    Rol_at (%d, %d);\n" index amount
  | Swap (left, right) ->
      Printf.fprintf channel "    Swap (%d, %d);\n" left right
  | Feistel (left, right, key) ->
      Printf.fprintf channel "    Feistel (%d, %d, %d);\n" left right key

let escaped_bytes bytes =
  let buffer = Buffer.create (Bytes.length bytes * 4) in
  Bytes.iter
    (fun value ->
      Buffer.add_string buffer (Printf.sprintf "\\x%02x" (Char.code value)))
    bytes;
  Buffer.contents buffer

let write_program path tape target =
  let channel = open_out_bin path in
  Fun.protect
    ~finally:(fun () -> close_out_noerr channel)
    (fun () ->
      output_string channel "open Tape_types\n\n";
      output_string channel "let capsule : capsule =\n";
      output_string channel "  {\n";
      Printf.fprintf channel "    marker_a = 0x%x;\n" marker_a;
      Printf.fprintf channel "    marker_b = 0x%x;\n" marker_b;
      Printf.fprintf channel "    width = %d;\n" width;
      output_string channel "    tape = [|\n";
      Array.iter (output_operation channel) tape;
      output_string channel "    |];\n";
      Printf.fprintf channel "    target = \"%s\";\n" (escaped_bytes target);
      Printf.fprintf channel "    marker_c = 0x%x;\n" marker_c;
      output_string channel "  }\n")

let count_operations tape =
  let counts = Array.make 5 0 in
  Array.iter
    (function
      | Xor_at _ -> counts.(0) <- counts.(0) + 1
      | Add_at _ -> counts.(1) <- counts.(1) + 1
      | Rol_at _ -> counts.(2) <- counts.(2) + 1
      | Swap _ -> counts.(3) <- counts.(3) + 1
      | Feistel _ -> counts.(4) <- counts.(4) + 1)
    tape;
  counts

let write_manifest path tape =
  let counts = count_operations tape in
  let channel = open_out path in
  Fun.protect
    ~finally:(fun () -> close_out_noerr channel)
    (fun () ->
      Printf.fprintf channel "format=tagged-tape-v1\n";
      Printf.fprintf channel "ocaml_value_width=64\n";
      Printf.fprintf channel "payload_width=%d\n" width;
      Printf.fprintf channel "operation_count=%d\n" (Array.length tape);
      Printf.fprintf channel "xor_at=%d\n" counts.(0);
      Printf.fprintf channel "add_at=%d\n" counts.(1);
      Printf.fprintf channel "rol_at=%d\n" counts.(2);
      Printf.fprintf channel "swap=%d\n" counts.(3);
      Printf.fprintf channel "feistel=%d\n" counts.(4))

let payload_of_flag flag =
  if String.length flag <> width + 6 then invalid_arg "unexpected flag length";
  if String.sub flag 0 5 <> "KCTF{" || flag.[String.length flag - 1] <> '}'
  then invalid_arg "unexpected flag wrapper";
  let payload = String.sub flag 5 width in
  String.iter
    (function
      | '0' .. '9' | 'a' .. 'f' -> ()
      | _ -> invalid_arg "flag payload must be lowercase hexadecimal")
    payload;
  payload

let argument name =
  let rec search index =
    if index + 1 >= Array.length Sys.argv then
      invalid_arg ("missing argument " ^ name)
    else if Sys.argv.(index) = name then Sys.argv.(index + 1)
    else search (index + 1)
  in
  search 1

let () =
  let flag_path = argument "--flag-file" in
  let seed_path = argument "--seed-file" in
  let output_path = argument "--output" in
  let manifest_path = argument "--manifest" in
  let flag = read_line_exact flag_path in
  let seed = decode_hex (read_line_exact seed_path) in
  let rng = { state = seed_state seed } in
  let tape = make_tape rng in
  let state = Bytes.of_string (payload_of_flag flag) in
  Array.iter (Engine.apply state) tape;
  write_program output_path tape state;
  write_manifest manifest_path tape

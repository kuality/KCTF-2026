let prefix = "KCTF{"

let extract_payload line width =
  let expected_length = String.length prefix + width + 1 in
  if String.length line <> expected_length then None
  else if String.sub line 0 (String.length prefix) <> prefix then None
  else if String.get line (expected_length - 1) <> '}' then None
  else Some (Bytes.of_string (String.sub line (String.length prefix) width))

let verify line =
  let capsule = Program_data.capsule in
  match extract_payload line capsule.width with
  | None -> false
  | Some payload ->
      let transformed = Engine.run capsule payload in
      Engine.constant_time_equal transformed capsule.target

let () =
  print_string "flag> ";
  flush stdout;
  let accepted =
    try verify (input_line stdin) with
    | End_of_file -> false
    | Invalid_argument _ -> false
  in
  print_endline (if accepted then "Correct." else "Wrong.")

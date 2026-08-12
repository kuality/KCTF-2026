open Tape_types

let byte_get state index = Char.code (Bytes.get state index)

let byte_set state index value =
  Bytes.set state index (Char.chr (value land 0xff))

let rol8 value amount =
  let amount = amount land 7 in
  if amount = 0 then value land 0xff
  else
    ((value lsl amount) lor (value lsr (8 - amount))) land 0xff

let round_function value key =
  let amount = ((key lsr 5) land 7) + 1 in
  rol8 ((value + key) land 0xff) amount
  lxor ((key * 0x5b + 0x33) land 0xff)

let apply state = function
  | Xor_at (index, key) ->
      byte_set state index (byte_get state index lxor key)
  | Add_at (index, key) ->
      byte_set state index (byte_get state index + key)
  | Rol_at (index, amount) ->
      byte_set state index (rol8 (byte_get state index) amount)
  | Swap (left, right) ->
      let a = byte_get state left in
      let b = byte_get state right in
      byte_set state left b;
      byte_set state right a
  | Feistel (left, right, key) ->
      let a = byte_get state left in
      let b = byte_get state right in
      byte_set state left b;
      byte_set state right (a lxor round_function b key)

let valid_capsule capsule =
  capsule.marker_a = 0x13579bdf
  && capsule.marker_b = 0x02468ace
  && capsule.marker_c = 0x11111151
  && capsule.width = String.length capsule.target
  && capsule.width = 64

let run capsule payload =
  if not (valid_capsule capsule) then invalid_arg "damaged archive";
  if Bytes.length payload <> capsule.width then invalid_arg "bad width";
  let state = Bytes.copy payload in
  Array.iter (apply state) capsule.tape;
  state

let constant_time_equal bytes expected =
  if Bytes.length bytes <> String.length expected then false
  else
    let difference = ref 0 in
    for index = 0 to Bytes.length bytes - 1 do
      difference :=
        !difference
        lor (Char.code (Bytes.get bytes index)
             lxor Char.code (String.get expected index))
    done;
    !difference = 0

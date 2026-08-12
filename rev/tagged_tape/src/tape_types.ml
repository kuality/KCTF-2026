type op =
  | Xor_at of int * int
  | Add_at of int * int
  | Rol_at of int * int
  | Swap of int * int
  | Feistel of int * int * int

type capsule = {
  marker_a : int;
  marker_b : int;
  width : int;
  tape : op array;
  target : string;
  marker_c : int;
}

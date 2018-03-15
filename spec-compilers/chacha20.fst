module Chacha20
open Spec.Lib.IntTypes
open Spec.Lib.IntSeq
open Speclib
let blocksize = 0x40 
let index_t = range_t 0x0 0x10 
let rotval_t = range_t 0x1 0x20 
let state_t = array_t uint32_t 0x10 
let key_t = bytes_t 0x20 
let nonce_t = bytes_t 0xc 
let block_t = bytes_t 0x40 
let line (a:index_t) (b:index_t) (d:index_t) (s:rotval_t) (m:state_t) : state_t =
  let m : state_t = copy m in 
  let m = m.[a] <- (m.[a] +. m.[b]) in 
  let m = m.[d] <- (m.[d] ^. m.[a]) in 
  let m = m.[d] <- rotate_left m.[d] (u32 s) in 
  m 
let quarter_round (a:index_t) (b:index_t) (c:index_t) (d:index_t) (m:state_t) : state_t =
  let m = line a b d 0x10 m in 
  let m = line c d b 0xc m in 
  let m = line a b d 0x8 m in 
  let m = line c d b 0x7 m in 
  m 
let double_round (m:state_t) : state_t =
  let m = quarter_round 0x0 0x4 0x8 0xc m in 
  let m = quarter_round 0x1 0x5 0x9 0xd m in 
  let m = quarter_round 0x2 0x6 0xa 0xe m in 
  let m = quarter_round 0x3 0x7 0xb 0xf m in 
  let m = quarter_round 0x0 0x5 0xa 0xf m in 
  let m = quarter_round 0x1 0x6 0xb 0xc m in 
  let m = quarter_round 0x2 0x7 0x8 0xd m in 
  let m = quarter_round 0x3 0x4 0x9 0xe m in 
  m 
let constants : array_t uint32 0x4 = createL [ (u32 0x61707865); (u32 0x3320646e); (u32 0x79622d32); (u32 0x6b206574) ] 
let chacha20_init (k:key_t) (counter:uint32_t) (nonce:nonce_t) : state_t =
  let st = create 0x10 (u32 0x0) in 
  let st = update_slice st 0x0 0x4 constants in 
  let st = update_slice st 0x4 0xc (uints_from_bytes_le #U32 k) in 
  let st = st.[0xc] <- counter in 
  let st = update_slice st 0xd 0x10 (uints_from_bytes_le #U32 nonce) in 
  st 
let chacha20_core (st:state_t) : state_t =
  let working_state = copy st in 
  let working_state = repeati (range 0xa) (fun x working_state -> let working_state = double_round working_state in  working_state) working_state in 
  let working_state = repeati (range 0x10) (fun i working_state -> let working_state = working_state.[i] <- working_state.[i] +. st.[i] in  working_state) working_state in 
  working_state 
let chacha20 (k:key_t) (counter:uint32_t) (nonce:nonce_t) : state_t =
  chacha20_core (chacha20_init k counter nonce) 
let chacha20_block (k:key_t) (counter:uint32_t) (nonce:nonce_t) : block_t =
  let st = chacha20 k counter nonce in 
  let block = uints_to_bytes_le #U32 st in 
  block 
let xor_block (block:vlbytes_t) (keyblock:block_t) : vlbytes_t =
  let out = copy block in 
  let out = repeati (range (length out)) (fun i out -> let out = out.[i] <- out.[i] ^. keyblock.[i] in  out) out in 
  out 
let chacha20_counter_mode (key:key_t) (counter:uint32_t) (nonce:nonce_t) (msg:vlbytes_t) : vlbytes_t =
  let blocks = split_blocks msg blocksize in 
  let keyblock = create blocksize (u8 0x0) in 
  let (keyblock,blocks) = repeati (range 0x0 (length blocks)) (fun i (keyblock,blocks) -> let keyblock = chacha20_block key (counter +. (u32 i)) nonce in 
  let blocks = blocks.[i] <- xor_block blocks.[i] keyblock in  (keyblock,blocks)) (keyblock,blocks) in 
  concat_blocks blocks 
let chacha20_encrypt (key:key_t) (counter:uint32_t) (nonce:nonce_t) (msg:vlbytes_t) : vlbytes_t =
  chacha20_counter_mode key counter nonce msg 
let chacha20_decrypt (key:key_t) (counter:uint32_t) (nonce:nonce_t) (msg:vlbytes_t) : vlbytes_t =
  chacha20_counter_mode key counter nonce msg 

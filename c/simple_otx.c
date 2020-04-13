#include "ckb_syscalls.h"
#include "protocol.h"
#include "common.h"
#include "secp256k1_helper.h"
#include "keccak256.h"

#define INPUT_SIZE 128
#define SCRIPT_SIZE 32768
#define HASH_SIZE 32
#define SIGNATURE_SIZE 65
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 65  // ETH address uncompress pub key 
#define TEMP_SIZE 32768
#define RECID_INDEX 64

#define MAX_WITNESS_SIZE 32768

#define ERROR_TXFORMAT -5

static int verify_signature(unsigned char *message, unsigned char *lock_bytes, const void * lockargs){

  unsigned char temp[TEMP_SIZE];

  /* Load signature */
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  int ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, lock_bytes, lock_bytes[RECID_INDEX]) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  /* Check pubkey hash */
  size_t pubkey_size = PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_UNCOMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, &temp[1], pubkey_size - 1);
  keccak_final(&sha3_ctx, temp);

  if (memcmp(lockargs, &temp[12], BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  return CKB_SUCCESS;
}

/* calculate hash  = all input with the same lock script hash  + all output of same index as input*/
static int get_simple_otx_hash(unsigned char* otx_hash){

  /* empty hash */
  unsigned char empty_hash[HASH_SIZE] = {
    0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  };

  unsigned char input[INPUT_SIZE];
  uint64_t input_len = INPUT_SIZE;
  uint64_t len = 0;
  int ret = 0;

  size_t index = 0;
  uint64_t output_capacity = 0;
  unsigned char current_script_hash[HASH_SIZE];
  unsigned char output_temp_hash[HASH_SIZE];
  unsigned char script_hash[HASH_SIZE];

  /* load script hash*/
  len = HASH_SIZE;
  ret = ckb_load_script_hash(script_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != HASH_SIZE) {
    return ERROR_SYSCALL;
  }

  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);

  while (1) {
    len = HASH_SIZE;
    ret = ckb_load_cell_by_field(current_script_hash, &len, 0, index,
                                 CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK_HASH);

    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }

    if (ret == CKB_ITEM_MISSING) {
      index += 1;
      continue;
    }

    if (ret != CKB_SUCCESS) {
      return ret;
    }

    if (len != HASH_SIZE) {
      return -103;
    }

    /* check current input lock script hash equals script hash*/
    if ((len == HASH_SIZE) &&
        (memcmp(current_script_hash, script_hash, HASH_SIZE) == 0))
    {

      /* input: previous_outpoint + since */
      input_len = INPUT_SIZE;
      ret = ckb_load_input(input, &input_len, 0, index, CKB_SOURCE_INPUT);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
      if (input_len > INPUT_SIZE) {
        return -100;
      }
      keccak_update(&sha3_ctx, input, input_len);

      /* output: capacity + lock_script_hash + type_script_hash + output_data_hash */

      /* capacity */
      len = 8;
      ret = ckb_load_cell_by_field((unsigned char *)&output_capacity, &len, 0, index, 
                                CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY);
      if (ret == CKB_INDEX_OUT_OF_BOUND) {
        return ERROR_TXFORMAT;
      }
      if(ret != CKB_SUCCESS){
        return ret;
      }
      if (len != 8) {
        return ERROR_SYSCALL;
      }
      keccak_update(&sha3_ctx, (unsigned char *)&output_capacity, len);

      /* lock script hash*/
      len = HASH_SIZE;
      ret = ckb_load_cell_by_field(output_temp_hash, &len, 0, index, 
                                CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);

      if(ret == CKB_ITEM_MISSING){
        keccak_update(&sha3_ctx, empty_hash, HASH_SIZE);
      } else {
        if (ret == CKB_INDEX_OUT_OF_BOUND) {
          return ERROR_TXFORMAT;
        }
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        if (len != HASH_SIZE) {
          return ERROR_SYSCALL;
        }
        keccak_update(&sha3_ctx, output_temp_hash, len);
      }

      /* type script hash*/
      len = HASH_SIZE;
      ret = ckb_load_cell_by_field(output_temp_hash, &len, 0, index, 
                                CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH);
      if(ret == CKB_ITEM_MISSING){
        keccak_update(&sha3_ctx, empty_hash, HASH_SIZE);
      } else {
        if (ret == CKB_INDEX_OUT_OF_BOUND) {
          return ERROR_TXFORMAT;
        }
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        if (len != HASH_SIZE) {
          return ERROR_SYSCALL;
        }
        keccak_update(&sha3_ctx, output_temp_hash, len);
      }

      /* output data hash */
      len = HASH_SIZE;
      ret = ckb_load_cell_by_field(output_temp_hash, &len, 0, index, 
                                CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_DATA_HASH);
      if(ret == CKB_ITEM_MISSING || ret == CKB_INDEX_OUT_OF_BOUND){
        keccak_update(&sha3_ctx, empty_hash, HASH_SIZE);
      } else {
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        if (len != HASH_SIZE) {
          return ERROR_SYSCALL;
        }
        keccak_update(&sha3_ctx, output_temp_hash, len);
      }

    }
    index += 1;
  }

  keccak_final(&sha3_ctx, otx_hash);

  return CKB_SUCCESS;
}

/* the simple otx lock script only for one scenario:  
   1. otx.inputs.length === otx.outputs.length 
*/

int main()
{

  /* hash prefix for ethereum personal sign: Ethereum Signed Message */
  unsigned char eth_prefix[28]= {
0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x20, 0x53, 0x69 ,0x67, 0x6e , 
0x65 , 0x64 , 0x20 , 0x4d , 0x65 , 0x73 , 0x73, 0x61 , 0x67 , 0x65 , 0x3a , 0x0a , 0x33 , 0x32
  };

  unsigned char temp[TEMP_SIZE];
  unsigned char lock_bytes[SIGNATURE_SIZE];

  unsigned char script[SCRIPT_SIZE];
  unsigned char tx_hash[HASH_SIZE];
  unsigned char message[HASH_SIZE];

  SHA3_CTX sha3_ctx;

  /*load script args*/
  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len > SCRIPT_SIZE) {
    return -101;
  }

  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return -102;
  }
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);

  /* Load witness of first input */
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  if (lock_bytes_seg.size != SIGNATURE_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_seg.size);

  ret = get_simple_otx_hash(tx_hash);
  if(ret != CKB_SUCCESS){
    return ret;
  }

  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, tx_hash, HASH_SIZE);

  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  keccak_update(&sha3_ctx, (unsigned char *)&witness_len, sizeof(uint64_t));
  keccak_update(&sha3_ctx, temp, witness_len);

  size_t i = 1;
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    keccak_update(&sha3_ctx, (unsigned char *)&len, sizeof(uint64_t));
    keccak_update(&sha3_ctx, temp, len);
    i += 1;
  }
  keccak_final(&sha3_ctx, message);

  /* verify signature using tx_hash*/
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, eth_prefix, 28);
  keccak_update(&sha3_ctx, message, 32);
  keccak_final(&sha3_ctx, message);

  return verify_signature(message, lock_bytes, args_bytes_seg.ptr);

}
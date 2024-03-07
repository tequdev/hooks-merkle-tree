#include "hookapi.h"

#define PROOF_LENGTH 3

#define LEAF_LENGTH 20
#define LEAF_INDEX 1
#define BLOB_LENGTH 1 + 32 * PROOF_LENGTH + LEAF_LENGTH + LEAF_INDEX

#define CURRENT_ELEMENT_GUARD 32 * PROOF_LENGTH + 2
#define HASH_DATA_GUARD 64 * PROOF_LENGTH + 2
#define HASH_OUT_GUARD 32 * PROOF_LENGTH + 2

int64_t hook(uint32_t reserved) {

  REQUIRE(otxn_type == sfBlob, "Invalid transaction type");

  // buffer = blob_len + sfBlob
  ASSERT(otxn_slot(1) == 1);
  ASSERT(slot_subfield(1, sfBlob, 2) == 2);

  uint8_t buffer[BLOB_LENGTH];
  REQUIRE(slot(SBUF(buffer), 2) > 0, "Blob field not found");

  uint8_t proof_root[32];
  REQUIRE(hook_param(SBUF(proof_root), "RT", 2) > 0,
          "Hook Paramter 'RT' not found");

  // len = blob_len
  // ptr = sfBlob
  uint16_t len = (uint16_t)buffer[0];
  uint8_t *ptr = buffer + 1;
  if (len > 192) {
    len = 193 + ((len - 193) * 256) + ((uint16_t)(buffer[1]));
    ptr++;
  }

  // leaf index
  uint8_t index = ptr[32 * PROOF_LENGTH + LEAF_LENGTH]; // last byte

  // hash = leaf
  uint8_t leaf[LEAF_LENGTH];
  for (int i = 0; GUARD(LEAF_LENGTH), i < LEAF_LENGTH; i++) {
    leaf[i] = ptr[32 * PROOF_LENGTH + i]; // leaf
  }

  uint8_t hash[32];
  util_sha512h(SBUF(hash), SBUF(leaf));

  for (int i = 0; GUARD(PROOF_LENGTH), i < PROOF_LENGTH; i++) {
    uint8_t currentElement[32];
    for (int j = 0; GUARD(CURRENT_ELEMENT_GUARD), j < 32; j++) {
      currentElement[j] = ptr[i * 32 + j];
    }

    // data = hash + currentElement (if left leaf)
    // data = currentElement + hash (if right leaf)
    uint8_t data[64];
    for (int j = 0; GUARD(HASH_DATA_GUARD), j < 64; j++) {
      if (index % 2 == 0)
        data[j] = j < 32 ? hash[j] : currentElement[j - 32];
      else
        data[j] = j < 32 ? currentElement[j] : hash[j - 32];
    }

    uint8_t hash_out[32];
    ASSERT(util_sha512h(SBUF(hash_out), SBUF(data)) > 0);

    // hash = hash_out
    for (int j = 0; GUARD(HASH_OUT_GUARD), j < 32; j++) {
      hash[j] = hash_out[j];
    }
    index = index / 2;
  }

  // if (hash != PROOF_ROOT) rollback(SBUF("Invalid proof"), __LINE__);
  for (int i = 0; GUARD(32), i < 32; i++) {
    if (hash[i] != proof_root[i])
      rollback(SBUF("Invalid proof"), __LINE__);
  }
  // REQUIRE(BUFFER_EQUAL_32(hash, PROOF_ROOT), "Invalid proof");

  accept(SBUF("Valid proof"), __LINE__);

  return 0;
}

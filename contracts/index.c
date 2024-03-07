#include "hookapi.h"

#define PROOF_LENGTH 3

#define LEAF_LENGTH 20
#define LEAF_INDEX 1
#define BLOB_LENGTH 1 + 32 * PROOF_LENGTH + LEAF_LENGTH + LEAF_INDEX

#define CURRENT_ELEMENT_GUARD 32 * PROOF_LENGTH + 2
#define HASH_DATA_GUARD 64 * PROOF_LENGTH + 2
#define HASH_OUT_GUARD 32 * PROOF_LENGTH + 2

#define COPY_UINT256(buf_raw, i)                                               \
  {                                                                            \
    unsigned char *buf = (unsigned char *)buf_raw;                             \
    *(uint64_t *)(buf + 0) = *(uint64_t *)(i + 0);                             \
    *(uint64_t *)(buf + 8) = *(uint64_t *)(i + 8);                             \
    *(uint64_t *)(buf + 16) = *(uint64_t *)(i + 16);                           \
    *(uint64_t *)(buf + 24) = *(uint64_t *)(i + 24);                           \
  }

int64_t hook(uint32_t reserved) {

  REQUIRE(otxn_type() == ttINVOKE, "Invalid transaction type");

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

  // leaf
  uint8_t leaf[LEAF_LENGTH];
  for (int i = 0; GUARD(LEAF_LENGTH), i < LEAF_LENGTH; i++) {
    leaf[i] = ptr[32 * PROOF_LENGTH + i]; // leaf
  }

  // hash = hash(leaf)
  uint8_t hash[32];
  util_sha512h(SBUF(hash), SBUF(leaf));

  // loop for proofs
  for (int i = 0; GUARD(PROOF_LENGTH), i < PROOF_LENGTH; i++) {
    uint8_t currentElement[32];
    COPY_UINT256(currentElement, ptr + i * 32);

    uint8_t data[64];

    if (index % 2 == 0) {
      // data = hash + currentElement (if left leaf)
      COPY_UINT256(data, hash);
      COPY_UINT256(data + 32, currentElement);
    } else {
      // data = currentElement + hash (if right leaf)
      COPY_UINT256(data, currentElement);
      COPY_UINT256(data + 32, hash);
    }

    uint8_t hash_out[32];
    ASSERT(util_sha512h(SBUF(hash_out), SBUF(data)) > 0);

    // hash = hash_out
    COPY_UINT256(hash, hash_out);
    index = index / 2;
  }

  // if (hash != proof_root) rollback(SBUF("Invalid proof"), __LINE__);
  for (int i = 0; GUARD(32), i < 32; i++) {
    if (hash[i] != proof_root[i])
      rollback(SBUF("Invalid proof"), __LINE__);
  }
  // REQUIRE(BUFFER_EQUAL_32(hash, proof_root), "Invalid proof");

  accept(SBUF("Valid proof"), __LINE__);

  return 0;
}

import os
import random
import string

class DemoBlockCipher:
    BLOCK_SIZE = 16
    ROUNDS = 12

    def __init__(self, master_key: bytes):
        """
        Initialize the cipher with a master key of at least 256 bits (32 bytes).
        The same master_key must be used for both encryption and decryption
        to maintain consistency.
        """
        if len(master_key) < 32:
            raise ValueError("Master key must be at least 256 bits (32 bytes).")
        self.master_key = master_key

        # Initialize deterministic random generator from master_key
        # for consistent S-box generation
        rnd = random.Random(int.from_bytes(self.master_key, 'big'))

        # Create a deterministic S-box based on master_key
        self.SBOX = list(range(256))
        for i in reversed(range(1, 256)):
            j = rnd.randrange(i + 1)
            self.SBOX[i], self.SBOX[j] = self.SBOX[j], self.SBOX[i]

        self.INV_SBOX = [0]*256
        for i, val in enumerate(self.SBOX):
            self.INV_SBOX[val] = i

    def sub_bytes(self, block: bytes, inverse: bool = False) -> bytes:
        sbox_table = self.INV_SBOX if inverse else self.SBOX
        return bytes(sbox_table[b] for b in block)

    def inv_sub_bytes(self, block: bytes) -> bytes:
        return self.sub_bytes(block, inverse=True)

    def shift_rows(self, block: bytes, inverse: bool = False) -> bytes:
        matrix = [list(block[i*4:(i+1)*4]) for i in range(4)]
        for i in range(4):
            if inverse:
                # shift right by i
                matrix[i] = matrix[i][-i:] + matrix[i][:-i]
            else:
                # shift left by i
                matrix[i] = matrix[i][i:] + matrix[i][:i]
        return bytes(matrix[r][c] for r in range(4) for c in range(4))

    def inv_shift_rows(self, block: bytes) -> bytes:
        return self.shift_rows(block, inverse=True)

    def mix_columns(self, block: bytes, inverse: bool = False) -> bytes:
        # Dummy mix_columns: just rotate columns
        matrix = [list(block[i*4:(i+1)*4]) for i in range(4)]
        for c in range(4):
            col = [matrix[r][c] for r in range(4)]
            if inverse:
                # rotate up
                col = col[-1:] + col[:-1]
            else:
                # rotate down
                col = col[1:] + col[:1]
            for r in range(4):
                matrix[r][c] = col[r]
        return bytes(matrix[r][c] for r in range(4) for c in range(4))

    def inv_mix_columns(self, block: bytes) -> bytes:
        return self.mix_columns(block, inverse=True)

    def add_round_key(self, block: bytes, round_key: bytes) -> bytes:
        return bytes(b ^ k for b, k in zip(block, round_key))

    def polialphabetic_shift(self, block: bytes, key_bits: int) -> bytes:
        # If LSB of key_bits is 1, swap first and last byte
        if key_bits & 1:
            block = bytearray(block)
            block[0], block[-1] = block[-1], block[0]
            block = bytes(block)
        return block

    def key_schedule(self) -> list:
        # Deterministic key schedule based on master_key
        # Use the same approach: seed a Random with master_key
        rnd = random.Random(int.from_bytes(self.master_key, 'big'))
        round_keys = []
        current_key = self.master_key[:16]

        for _ in range(self.ROUNDS):
            # Generate pseudo-random 16 bytes
            rand_block = bytes([rnd.randint(0, 255) for _ in range(16)])
            # XOR with current_key to produce round_key
            round_key = bytes(a ^ b for a, b in zip(current_key, rand_block))
            round_keys.append(round_key)
            current_key = round_key

        return round_keys

    def encrypt_block(self, plaintext_block: bytes) -> bytes:
        if len(plaintext_block) != self.BLOCK_SIZE:
            raise ValueError(f"Plaintext block must be {self.BLOCK_SIZE} bytes.")

        round_keys = self.key_schedule()
        state = self.add_round_key(plaintext_block, round_keys[0])

        for i in range(1, self.ROUNDS):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            if i != self.ROUNDS - 1:
                state = self.mix_columns(state)
            key_bits = round_keys[i][0]
            state = self.polialphabetic_shift(state, key_bits)
            state = self.add_round_key(state, round_keys[i])

        return state

    def decrypt_block(self, ciphertext_block: bytes) -> bytes:
        if len(ciphertext_block) != self.BLOCK_SIZE:
            raise ValueError(f"Ciphertext block must be {self.BLOCK_SIZE} bytes.")

        round_keys = self.key_schedule()
        # Reverse order of operations
        state = ciphertext_block

        for i in range(self.ROUNDS - 1, 0, -1):
            state = self.add_round_key(state, round_keys[i])
            key_bits = round_keys[i][0]
            state = self.polialphabetic_shift(state, key_bits)
            if i != self.ROUNDS - 1:
                state = self.inv_mix_columns(state)
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)

        state = self.add_round_key(state, round_keys[0])
        return state


def pad_data(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]*pad_len)

def unpad_data(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError("Invalid padding")
    # Check all padding bytes are the same
    if any(data[-i] != pad_len for i in range(1, pad_len+1)):
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def encrypt_data(plaintext: bytes, master_key: bytes) -> bytes:
    plaintext = pad_data(plaintext, DemoBlockCipher.BLOCK_SIZE)
    cipher = DemoBlockCipher(master_key)
    ciphertext = b""
    for i in range(0, len(plaintext), DemoBlockCipher.BLOCK_SIZE):
        block = plaintext[i:i+DemoBlockCipher.BLOCK_SIZE]
        encrypted_block = cipher.encrypt_block(block)
        ciphertext += encrypted_block
    return ciphertext

def decrypt_data(ciphertext: bytes, master_key: bytes) -> bytes:
    if len(ciphertext) % DemoBlockCipher.BLOCK_SIZE != 0:
        raise ValueError("Ciphertext not multiple of block size")
    cipher = DemoBlockCipher(master_key)
    plaintext_padded = b""
    for i in range(0, len(ciphertext), DemoBlockCipher.BLOCK_SIZE):
        cblock = ciphertext[i:i+DemoBlockCipher.BLOCK_SIZE]
        pblock = cipher.decrypt_block(cblock)
        plaintext_padded += pblock
    return unpad_data(plaintext_padded)


# ===== Example usage =====
if __name__ == "__main__":
    master_key = os.urandom(32)  # 256-bit master key
    plaintext = b"Hello world"

    ciphertext = encrypt_data(plaintext, master_key)
    print("Master Key (hex):", master_key.hex())
    print("Plaintext:", plaintext)
    print("Ciphertext (hex):", ciphertext.hex())

    decrypted = decrypt_data(ciphertext, master_key)
    print("Decrypted:", decrypted)

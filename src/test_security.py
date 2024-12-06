import os
import pytest
from src.main import DemoBlockCipher, encrypt_data, decrypt_data

# In this test file, we verify that the DemoBlockCipher does not meet recognized cryptographic standards.
# The tests are designed to fail or highlight non-compliance when compared to known good practices and standardized algorithms.

@pytest.mark.parametrize("plaintext", [
    b"Hello World!    ",  # exactly 16 bytes
    b"Test1234Test1234",  # another 16-byte sample
])
def test_key_length(plaintext):
    """
    Check if the cipher can handle a 256-bit key.
    Having a 256-bit key is a baseline property but does not guarantee compliance with standards.
    This test merely confirms the key length is correct; it does not validate the entire algorithm.
    """
    master_key = os.urandom(32)
    cipher = DemoBlockCipher(master_key)
    # Assert that the key length is 256 bits as a minimal criterion.
    assert len(master_key) == 32, "Key must be 256 bits."

def test_known_standard_mode():
    """
    Attempt to compare the DemoBlockCipher to a known AES test vector.
    AES test vectors are standardized, so a compliant cipher would produce a known output.
    Since DemoBlockCipher uses a custom S-box and non-standard operations,
    it will not match the AES test vector output.
    This test demonstrates that the cipher does not align with known standards.
    """
    master_key = bytes([0x00]*32)  # A 256-bit zeroed key
    cipher = DemoBlockCipher(master_key)

    plaintext_block = bytes([0x00]*16)
    # A known AES-256 ECB test vector (e.g., from NIST) will have a specific ciphertext.
    # The DemoBlockCipher output should differ, confirming non-compliance.
    expected_aes_output = bytes.fromhex("c34c052cc0da8d73451afe5f03be297f")

    output = cipher.encrypt_block(plaintext_block)
    assert output != expected_aes_output, "Unexpected match with AES test vector!"

def test_no_standard_mode():
    """
    Verify that no recognized mode of operation (e.g., CBC, CTR, GCM) is used.
    The DemoBlockCipher encrypts blocks directly without employing a NIST-approved mode.
    As a result, the test will deliberately fail to highlight that this cipher does not comply
    with standard recommendations on modes of operation.
    """
    master_key = os.urandom(32)
    plaintext = b"Hello World!"
    ciphertext = encrypt_data(plaintext, master_key)
    decrypted = decrypt_data(ciphertext, master_key)
    assert decrypted == plaintext, "Basic encryption/decryption should work on its own."

    # However, just because it encrypts/decrypts does not mean it meets standards.
    # Fail the test to indicate the absence of a recognized mode:
    pytest.fail("No NIST-approved mode (CBC, CTR, GCM) detected. Non-compliant with standards.")

def test_random_sbox():
    """
    Check the usage of the S-box.
    In standard algorithms like AES, the S-box is fixed, well-studied, and mathematically defined.
    Here, the S-box is random and derived from the key, with no known cryptographic analysis.
    This test will fail to indicate that the S-box usage is not standard-compliant.
    """
    master_key = os.urandom(32)
    cipher = DemoBlockCipher(master_key)

    # For AES, the S-box[0x00] is known to be 0x63. This algorithm’s S-box is unknown and non-standard.
    aes_sbox_00 = 0x63
    # If by some unlikely coincidence they match, we still fail, because the S-box is not from a known standard.
    if cipher.SBOX[0] == aes_sbox_00:
        pytest.fail("S-box unexpectedly matches AES, but still has no security proof.")

    pytest.fail("Custom S-box does not follow any recognized standard. Non-compliant.")

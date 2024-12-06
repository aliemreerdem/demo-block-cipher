# DemoBlockCipher Project

This project presents an **educational** example of a custom block cipher algorithm. The algorithm is entirely non-standard, not cryptographically analyzed, and does not adhere to established cryptographic standards. The purpose is to illustrate the complexity of designing a secure cipher and to demonstrate why adherence to standardized, proven algorithms is crucial.

## Overview

- **DemoBlockCipher Class:**  
  This class implements a fictional block cipher that uses:
  - A custom S-Box derived deterministically from the master key (not a standard, analyzed S-box).
  - A rudimentary `mix_columns` and `shift_rows` step.
  - A polialphabetic_shift mechanism based on the round key bits.
  
  While these operations mimic certain aspects of known ciphers, none of these steps are mathematically grounded or security-evaluated. This is not AES, DES, or any recognized cipher.

- **Key and Encryption Process:**  
  The cipher requires a 256-bit (32-byte) master key. From this key, a series of round keys is derived. The algorithm applies 12 rounds of transformations to 16-byte blocks of data.

- **Padding, Encryption, and Decryption Functions:**  
  `encrypt_data` and `decrypt_data` handle arbitrary-length input by applying PKCS#7-like padding and processing data block-by-block. However, since no authenticated or approved mode of operation (CBC, CTR, GCM, etc.) is used, this approach does not guarantee actual security.

## Security Standards Evaluation

This algorithm is **not compliant with any industry or NIST standard**. Here are some reasons:

- **Non-Standard S-Box:**  
  Unlike AES’s mathematically defined S-box, this cipher uses a S-box generated from the master key, with no known security proofs.
  
- **Undefined Key Schedule:**  
  The key schedule is a simple XOR-based approach with pseudo-randomness, not an accepted design from standards.

- **No Recognized Cipher Mode:**  
  The cipher operates directly on blocks without using a proven mode such as CBC, CTR, or GCM. Standards (e.g., NIST SP 800-38A) recommend always using approved modes.

- **No Mathematical Security Assurance:**  
  The transformations (mix_columns, shift_rows, polialphabetic_shift) are not derived from known cryptographic constructs or analyzed for security.

In summary, this algorithm does not meet any recognized security standards or guidelines.

## Testing

The included test files, run with `pytest`, demonstrate the algorithm’s lack of adherence to established cryptographic standards. Some tests compare the cipher's behavior to known AES test vectors, which it cannot match, thereby showing non-compliance. Other tests fail deliberately to highlight the absence of standard modes or recognized S-box usage.

### Running the Tests

1. Install the required dependencies:
   ```bash
   pip install pytest

2. Run the tests:
   ```bash
   pytest test_security.py -v

3. You will see that certain tests fail. This is expected. These failures indicate that the algorithm does not comply with standard cryptographic practices.

## Example Test Scenarios

**Key Length Test:**
Verifies the key is at least 256 bits, which meets a basic length requirement but is insufficient by itself to ensure standard compliance.

**Known Standard Mode Comparison:**
Attempts to match AES test vectors. The DemoBlockCipher fails these tests, proving it does not adhere to the AES standard.

**No Standard Mode Usage:**
Tests confirm that no recommended NIST mode (e.g., CBC, CTR, GCM) is employed, resulting in a test failure that documents this non-compliance.

**Random S-Box Check:**
The test ensures the custom S-box does not match any known standard. It fails the test, emphasizing the lack of standardized S-box usage.

## Conclusion
The DemoBlockCipher serves as a learning tool, showcasing how easy it is to create a cipher-like structure that does not meet established security standards. The provided tests underscore the importance of using well-analyzed, standardized encryption methods (e.g., AES-256-GCM) for real-world applications. This project should never be used for securing sensitive data.
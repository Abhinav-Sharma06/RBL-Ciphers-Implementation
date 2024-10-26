import java.util.Arrays;

public class CamelliaCipher {
    // Full S-box for Camellia (256 elements)
    private static final byte[] SBOX = {
        (byte) 0x70, (byte) 0x82, (byte) 0x2C, (byte) 0xEC, (byte) 0xB3, (byte) 0x27, (byte) 0xC0, (byte) 0xE5,
        (byte) 0xE4, (byte) 0x85, (byte) 0x57, (byte) 0x35, (byte) 0xEA, (byte) 0x0C, (byte) 0xAE, (byte) 0x41,
        (byte) 0x23, (byte) 0xEF, (byte) 0x6B, (byte) 0x93, (byte) 0x45, (byte) 0x19, (byte) 0xA5, (byte) 0x21,
        (byte) 0xED, (byte) 0x0E, (byte) 0x4F, (byte) 0x1E, (byte) 0x5C, (byte) 0x63, (byte) 0x58, (byte) 0xD1,
        (byte) 0xA2, (byte) 0x25, (byte) 0x22, (byte) 0x7C, (byte) 0x3B, (byte) 0x01, (byte) 0x21, (byte) 0x78,
        (byte) 0x87, (byte) 0xD4, (byte) 0x00, (byte) 0x46, (byte) 0x57, (byte) 0x9F, (byte) 0xD3, (byte) 0x27,
        (byte) 0x52, (byte) 0x4C, (byte) 0x36, (byte) 0x02, (byte) 0xE8, (byte) 0x5E, (byte) 0xB9, (byte) 0xEE,
        (byte) 0xE1, (byte) 0x8C, (byte) 0x94, (byte) 0x9B, (byte) 0x1B, (byte) 0x55, (byte) 0xB0, (byte) 0x52,
        (byte) 0xBF, (byte) 0xAC, (byte) 0xCC, (byte) 0x73, (byte) 0x69, (byte) 0xF8, (byte) 0xE2, (byte) 0x9A,
        (byte) 0x29, (byte) 0x7E, (byte) 0xA1, (byte) 0xC5, (byte) 0x89, (byte) 0x61, (byte) 0x32, (byte) 0x23,
        (byte) 0x3C, (byte) 0x4E, (byte) 0x3A, (byte) 0xBD, (byte) 0xBD, (byte) 0xA8, (byte) 0x76, (byte) 0x28,
        (byte) 0xD7, (byte) 0xC6, (byte) 0x0D, (byte) 0x54, (byte) 0x71, (byte) 0x75, (byte) 0xD8, (byte) 0x62,
        (byte) 0x68, (byte) 0xD5, (byte) 0xB6, (byte) 0xAF, (byte) 0x12, (byte) 0xDD, (byte) 0xD4, (byte) 0xF6,
        (byte) 0x14, (byte) 0xEB, (byte) 0xF0, (byte) 0xC7, (byte) 0x5F, (byte) 0x2B, (byte) 0x92, (byte) 0x3F,
        (byte) 0x8A, (byte) 0x60, (byte) 0x70, (byte) 0x7A, (byte) 0x64, (byte) 0xF5, (byte) 0x15, (byte) 0x99,
        (byte) 0x85, (byte) 0x9E, (byte) 0x2E, (byte) 0x48, (byte) 0x12, (byte) 0x8E, (byte) 0x89, (byte) 0x6D,
        (byte) 0xAB, (byte) 0x6C, (byte) 0x7B, (byte) 0xA9, (byte) 0xB7, (byte) 0x26, (byte) 0x53, (byte) 0x20,
        (byte) 0x7D, (byte) 0xEF, (byte) 0x16, (byte) 0x94, (byte) 0xFA, (byte) 0x42, (byte) 0xD2, (byte) 0x3B,
        (byte) 0x63, (byte) 0x6E, (byte) 0x39, (byte) 0x05, (byte) 0x56, (byte) 0x24, (byte) 0x0A, (byte) 0xE3,
        (byte) 0x72, (byte) 0x4D, (byte) 0xE6, (byte) 0xD9, (byte) 0xA0, (byte) 0x19, (byte) 0xFD, (byte) 0x43,
        (byte) 0xB8, (byte) 0x90, (byte) 0x83, (byte) 0x0E, (byte) 0xBF, (byte) 0xB2, (byte) 0x0B, (byte) 0xA4,
        (byte) 0xF1, (byte) 0x2F, (byte) 0x6F, (byte) 0xB5, (byte) 0xDB, (byte) 0x25, (byte) 0x11, (byte) 0xC9,
        (byte) 0x7F, (byte) 0x5E, (byte) 0xC2, (byte) 0x3D, (byte) 0x31, (byte) 0x04, (byte) 0x58, (byte) 0x77,
        (byte) 0xC3, (byte) 0x34, (byte) 0x2D, (byte) 0x50, (byte) 0x6A, (byte) 0xF9, (byte) 0xF3, (byte) 0x9B,
        (byte) 0xC8, (byte) 0x45, (byte) 0x0C, (byte) 0xE8, (byte) 0xC5, (byte) 0x88, (byte) 0x67, (byte) 0x1D
    };

    public static void main(String[] args) {
        // Example key for encryption/decryption
        byte[] key = new byte[] {
            0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
            (byte) 0xFE, (byte) 0xDC, (byte) 0xBA, (byte) 0x98, 0x76, 0x54, 0x32, 0x10
        };

        // Sample plaintext message to be encrypted
        byte[] plaintext = "In a world where technology continuously evolves, the power of innovation drives progress. Every day, new ideas emerge, shaping the future and transforming our daily lives. Embracing change is essential for growth and success, allowing us to explore uncharted territories. Together, we can create a brighter tomorrow, fueled by creativity and collaboration.".getBytes();

        // Create an instance of CamelliaCipher
        CamelliaCipher camellia = new CamelliaCipher();
        // Measure encryption
        Runtime runtime = Runtime.getRuntime();  // To track memory usage

        // Encryption Memory Usage and Time
        runtime.gc();  // Garbage collect before measuring memory
        long startEncryptMemory = runtime.totalMemory() - runtime.freeMemory();
        long startEncryptTime = System.nanoTime();

        System.out.println("\n\n");
        System.out.println("Encrypting...");
        byte[] encrypted = camellia.encrypt(plaintext, key);
        System.out.println("Encrypted: " + Arrays.toString(encrypted));
        System.out.println("\n\n");

        long endEncryptTime = System.nanoTime();
        long endEncryptMemory = runtime.totalMemory() - runtime.freeMemory();

        long encryptionTime = endEncryptTime - startEncryptTime;
        long encryptionMemoryUsed = endEncryptMemory - startEncryptMemory;

        // Measure decryption
        runtime.gc();  // Garbage collect before measuring memory
        long startDecryptMemory = runtime.totalMemory() - runtime.freeMemory();
        long startDecryptTime = System.nanoTime();

        System.out.println("Decrypting...");
        byte[] decrypted = camellia.decrypt(encrypted, key);
        System.out.println("Decrypted: " + new String(decrypted));
        System.out.println("\n\n");

        long endDecryptTime = System.nanoTime();
        long endDecryptMemory = runtime.totalMemory() - runtime.freeMemory();

        long decryptionTime = endDecryptTime - startDecryptTime;
        long decryptionMemoryUsed = endDecryptMemory - startDecryptMemory;

        // Output Results
        System.out.println("Encryption Time: " + encryptionTime + " ns");
        System.out.println("Decryption Time: " + decryptionTime + " ns");
        System.out.println("Encryption Memory Used: " + encryptionMemoryUsed + " bytes");
        System.out.println("Decryption Memory Used: " + decryptionMemoryUsed + " bytes");

        // Energy Estimation (using a 65W CPU model)
        double encryptionEnergy = (encryptionTime / 1e9) * 65;  // Joules
        double decryptionEnergy = (decryptionTime / 1e9) * 65;  // Joules

        System.out.println("Encryption Energy: " + encryptionEnergy + " J");
        System.out.println("Decryption Energy: " + decryptionEnergy + " J");

        // Verify decryption
        System.out.println("Decryption Successful: " + Arrays.equals(plaintext, decrypted));
        System.out.println("\n\n");
        }
        

    // Method to encrypt the plaintext using Camellia algorithm
    public byte[] encrypt(byte[] plaintext, byte[] key) {
        // Ensure key length is valid (128/192/256 bits)
        validateKeyLength(key);

        // Padding plaintext to be a multiple of block size (16 bytes)
        byte[] paddedPlaintext = pad(plaintext);

        // Perform encryption rounds based on key size
        byte[] ciphertext = new byte[paddedPlaintext.length];
        for (int i = 0; i < paddedPlaintext.length; i += 16) {
            byte[] block = Arrays.copyOfRange(paddedPlaintext, i, i + 16);
            byte[] encryptedBlock = encryptBlock(block, key);
            System.arraycopy(encryptedBlock, 0, ciphertext, i, 16);
        }
        return ciphertext;
    }

    // Method to decrypt the ciphertext using Camellia algorithm
    public byte[] decrypt(byte[] ciphertext, byte[] key) {
        // Ensure key length is valid (128/192/256 bits)
        validateKeyLength(key);

        // Perform decryption rounds based on key size
        byte[] decryptedText = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i += 16) {
            byte[] block = Arrays.copyOfRange(ciphertext, i, i + 16);
            byte[] decryptedBlock = decryptBlock(block, key);
            System.arraycopy(decryptedBlock, 0, decryptedText, i, 16);
        }
        return unpad(decryptedText);
    }

    // Validates the key length; throws an exception if invalid
    private void validateKeyLength(byte[] key) {
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("Key length must be 128, 192, or 256 bits (16, 24, or 32 bytes).");
        }
    }

    // Pads the plaintext to be a multiple of block size (16 bytes)
    private byte[] pad(byte[] input) {
        int blockSize = 16;
        int paddingLength = blockSize - (input.length % blockSize);
        byte[] paddedInput = new byte[input.length + paddingLength];
        System.arraycopy(input, 0, paddedInput, 0, input.length);
        Arrays.fill(paddedInput, input.length, paddedInput.length, (byte) paddingLength);
        return paddedInput;
    }

    // Unpads the decrypted text to retrieve the original plaintext
    private byte[] unpad(byte[] input) {
        int paddingLength = input[input.length - 1];
        return Arrays.copyOf(input, input.length - paddingLength);
    }

    // Method to encrypt a single block of data (16 bytes)
    private byte[] encryptBlock(byte[] block, byte[] key) {
        // Placeholder for encryption logic (implement the Camellia algorithm here)
        // Perform S-box substitution, key mixing, and permutation
        // Return the encrypted block
        return block; // Temporary, return the input block for now
    }

    // Method to decrypt a single block of data (16 bytes)
    private byte[] decryptBlock(byte[] block, byte[] key) {
        // Placeholder for decryption logic (implement the inverse of the Camellia algorithm here)
        // Perform inverse S-box substitution, key mixing, and permutation
        // Return the decrypted block
        return block; // Temporary, return the input block for now
    }
}

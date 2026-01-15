#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int build_signed_image(const char *input_file, const char *output_file,
                             const char *private_key_file, const char *aes_key_file);

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <input_binary> <output_image> <private_key> <aes_key>\n", argv[0]);
        printf("\n");
        printf("Arguments:\n");
        printf("  input_binary   - Binary file to sign (e.g., fsbl.bin)\n");
        printf("  output_image   - Output signed image file\n");
        printf("  private_key    - RSA private key file\n");
        printf("  aes_key        - AES-256 key file (32 bytes)\n");
        printf("\n");
        printf("Example:\n");
        printf("  %s fsbl.bin signed_fsbl.img private_key.der aes_key.bin\n", argv[0]);
        return 1;
    }

    const char *input_file = argv[1];
    const char *output_file = argv[2];
    const char *private_key_file = argv[3];
    const char *aes_key_file = argv[4];

    printf("BootROM Image Signer\n");
    printf("===================\n");
    printf("Input:  %s\n", input_file);
    printf("Output: %s\n", output_file);
    printf("Key:    %s\n", private_key_file);
    printf("AES:    %s\n", aes_key_file);
    printf("\n");

    int result = build_signed_image(input_file, output_file, private_key_file, aes_key_file);

    if (result == 0) {
        printf("Image signed successfully!\n");
        return 0;
    } else {
        printf("Signing failed!\n");
        return 1;
    }
}
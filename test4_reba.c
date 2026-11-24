#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char secret[] = "6?.7?34khi";

static void decode_password(char *out) {
    for (size_t i = 0; i < 10; i++) {
        out[i] = secret[i] ^ 0x5a;
    }
    out[10] = '\0';
}

static int check_password(char *input, char *password) {
    return strcmp(input, password) == 0;
}

int main(void) {
    char *input = malloc(128);
    char *password = malloc(64);

    if (input && password) {
        decode_password(password);
        printf("Password: ");
        if (!fgets(input, 128, stdin)) {
            free(input);
            free(password);
            return 1;
        }
        input[strcspn(input, "\n")] = '\0';

        int ok = check_password(input, password);
        if (ok) {
            puts("Access granted.");
        } else {
            puts("Wrong.");
        }

        free(input);
        free(password);
        return ok == 0;
    }

    free(input);
    free(password);
    return 1;
}

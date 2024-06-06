#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define IV_LEN 16  //  IV LEN
#define KEY_LEN 16 // KEY LEN

//{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

static const BYTE rgbIV[IV_LEN] = {0x59, 0x6f, 0x75, 0x47, 0x6f, 0x74, 0x4e, 0x6f, 0x6e, 0x74, 0x7a, 0x69, 0x6b, 0x65, 0x64, 0x21};   // IV: YouGotNontziked!
static const BYTE rgbKey[KEY_LEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}; // Encryption Key

BYTE *Assign_IV()
{
    // base address of the block created
    BYTE *ptr;
    int i;

    // Dynamically allocate memory using malloc()
    ptr = (BYTE *)calloc(IV_LEN, 1);

    // Check if the memory has been successfully
    // allocated by malloc or not
    if (ptr == NULL)
    {
        printf("Memory not allocated.\n");
        exit(0);
    }

    // Get the elements of the array
    for (i = 0; i < 16; i++)
        ptr[i] = rgbIV[i];

    return ptr;
}

BYTE *Assign_KEY()
{
    // base address of the block created
    BYTE *ptr;
    int i;

    // Dynamically allocate memory using malloc()
    ptr = (BYTE *)malloc(sizeof(rgbKey));

    // Check if the memory has been successfully
    // allocated by malloc or not
    if (ptr == NULL)
    {
        printf("Memory not allocated.\n");
        exit(0);
    }

    // Get the elements of the array
    for (i = 0; i < 16; ++i)
    {
        ptr[i] = rgbKey[i];
    }

    return ptr;
}

int main(int argc, __in_ecount(argc) LPWSTR *wargv)
{

    BYTE *pbKey = Assign_KEY();            // Pointer To The Key To Be Used Later
    BYTE *pbIV = Assign_IV();              // Pointer To The IV To Be Used Later
    BCRYPT_ALG_HANDLE phAlgorithm = NULL;  // Handle To The Encryption Algorithm
    BCRYPT_KEY_HANDLE phKey = NULL;        // Handle to the symmetric Key
    NTSTATUS status = STATUS_UNSUCCESSFUL; // BCrypt functions exit code
    ULONG pcbResult;                       // Points to the number of byted copied to pbOutput
    UCHAR pbOutput[4];                     // Pointer to the property value
    PBYTE pbKeyObject = NULL;              // Pointer to the key object
    FILE *source_file;                     // Handle to the encrypted file
    FILE *dest_file;                       // Handle to the decrypted file
    BYTE pbInput[16];                      // A pointer to the cipher-text
    char buffer[16];                       // A pointer to the plain-text
    char source_file_path[1024] = "C:\\Users\\Cyber-Administrator\\Desktop\\password list.txt.buga";
    char dest_file_path[1024];

    source_file = fopen(source_file_path, "rb");

    // open file for reading
    strcpy(dest_file_path, source_file_path);
    dest_file_path[strlen(dest_file_path) - 5] = '\0';
    dest_file = fopen(dest_file_path, "ab");
    printf(dest_file_path);
    if (!dest_file)
    {
        printf("Failed to open dest_file");
    }

    // Open an algorithm handle.
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&phAlgorithm, BCRYPT_AES_ALGORITHM, 0, 0)))
    {
        wprintf(L"Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    // Setting Encryption Property
    if (!NT_SUCCESS(status = BCryptSetProperty(phAlgorithm, L"ChainingMode", (PUCHAR)L"ChainingModeCBC", 0x20, 0)))
    {
        wprintf(L"Error 0x%x returned by BCryptSetProperty\n", status);
        goto Cleanup;
    }

    // Getting Encryption Property
    if (!NT_SUCCESS(status = BCryptGetProperty(phAlgorithm, BCRYPT_OBJECT_LENGTH, pbOutput, 4, &pcbResult, 0)))
    {
        printf("Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    // get 16 Bytes from files
    if (source_file)
    {

        // Allocate the key object on the heap.
        pbKeyObject = (PUCHAR)malloc(*(unsigned int *)pbOutput);
        if (NULL == pbKeyObject)
        {
            wprintf(L"ERROR memory allocation failed\n");
            goto Cleanup;
        }

        // Generate the key from supplied input key bytes.
        if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(phAlgorithm, &phKey, pbKeyObject, *(ULONG *)pbOutput, pbKey, KEY_LEN, 0)))
        {
            wprintf(L"Error 0x%x returned by BCryptGenerateSymmetricKey\n ", status);
            fprintf(stderr, "\nError number <%x>", GetLastError());
            goto Cleanup;
        }

        int counter = 0;

        memset(pbInput, 0, sizeof(pbInput));
        memset(buffer, 0, sizeof(buffer));

        // printf("\nBytes: [");
        while (fread(&pbInput[counter], 1, 1, source_file) == 1)
        {
            // printf("%x ", pbInput[counter]);
            if (++counter == 16) // Once pbInput's length is 16
            {
                // printf("]\n");
                BCryptDecrypt(phKey, (PUCHAR)pbInput, 0x10, 0, (PUCHAR)pbIV, 0x10, buffer, 0x10, &pcbResult, 0);
                memset(pbInput, 0, sizeof(pbInput));
                counter = 0;
                printf(buffer);
                // printf("\n\nBytes: [");
            }
        }
        // printf("]\n");

        // Padding The Remaining Block
        for (int i = counter; i < 16; i++)
        {
            pbInput[i] = 0;
        }

        // Decrypting the remaining Block in case it exists
        if (counter)
        {
            printf("\nHEX [%x]\n", pbInput);
            memset(buffer, 0, sizeof(buffer));
            BCryptDecrypt(phKey, (PUCHAR)pbInput, 0x10, 0, (PUCHAR)pbIV, 0x10, buffer, 0x10, &pcbResult, 0);
            printf(buffer);
        }
    }

    // Done!
    BCryptCloseAlgorithmProvider(phAlgorithm, 0);
    BCryptDestroyKey(phKey);
    fclose(source_file);

Cleanup:

    if (phAlgorithm)
    {
        BCryptCloseAlgorithmProvider(phAlgorithm, 0);
    }

    if (phKey)
    {
        BCryptDestroyKey(phKey);
    }

    if (pbKeyObject)
    {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }

    if (pbIV)
    {
        HeapFree(GetProcessHeap(), 0, pbIV);
    }
}
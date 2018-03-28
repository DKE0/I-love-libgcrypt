#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>

#define AES256_KEY_SIZE    16
#define AES256_BLOCK_SIZE  16
#define HMAC_KEY_SIZE      64
#define KDF_ITERATIONS     50000
#define KDF_SALT_SIZE      128
#define KDF_KEY_SIZE       AES256_KEY_SIZE + HMAC_KEY_SIZE

void cleanup(gcry_cipher_hd_t cipher , gcry_mac_hd_t mac, char *str, char *str2, char *str3 )
{
   if (cipher != NULL) gcry_cipher_close(cipher);
   if (mac != NULL) gcry_mac_close(mac);

   if (str != NULL) free(str);
   if (str2 != NULL) free(str2);
   if (str3 != NULL) free(str3);
}


size_t read_file_into_buf (char *filepath,unsigned char **data)
{
   long file_size;
   size_t bytes_read;
   FILE *f = fopen(filepath,"rb");

   if (f == NULL) {
	  fprintf(stderr,"Error: unable to open file %s\n", filepath);
	  return 0;
   }

   fseek(f,0, SEEK_END);
   file_size = ftell(f);
   fseek(f, 0, SEEK_SET);

   *data = malloc(file_size + 1);
   if (*data == NULL){
    fprintf(stderr, "Error : this file seems to be too long to fit in memory \n");
    fclose(f);
    return 0;
   }

   bytes_read = fread(*data, 1, file_size,f);
   if (bytes_read == 0)
   {
      free(*data);
   }

   fclose(f);

   return bytes_read;
}


size_t write_buf_to_file (char *filepath, unsigned char *data, unsigned int data_length)
{
   size_t bytes_written;
   FILE *f = fopen(filepath,"wb");
   if (f == NULL)
   {
       fprintf(stderr, "Error: unable to open file %s\n", filepath);
       return 0;
   }

   bytes_written = fwrite(data, 1, data_length, f);

   fclose(f);
   return bytes_written;
}

int init_cipher (gcry_cipher_hd_t *handle, unsigned char * key, unsigned char *init_vector ) {
   gcry_error_t err;

   err = gcry_cipher_open(handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);


if (err)
{
    fprintf(stderr, "cipher_open : %s / %s \n", gcry_strsource(err), gcry_strerror(err));
    return 1;
}

err = gcry_cipher_setkey(*handle , key , AES256_KEY_SIZE);
if (err)
{
   fprintf (stderr,"cipher_setkey :%s / %s \n", gcry_strsource(err), gcry_strerror(err));
   gcry_cipher_close(*handle);
   return 1;
}

err = gcry_cipher_setiv(*handle, init_vector, AES256_KEY_SIZE);

 if (err) {
    fprintf(stderr, "cipher_setiv: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
    gcry_cipher_close(*handle);
    return 1;
  }
  return 0;
}

int encrypt_file( char *infile, char *outfile, char * password) {
   unsigned char init_vector[AES256_BLOCK_SIZE],
                 kdf_salt[KDF_SALT_SIZE],
		 kdf_key[KDF_KEY_SIZE],
		 aes_key[AES256_KEY_SIZE],
		 hmac_key[HMAC_KEY_SIZE],
		 *hmac,
		 *packed_data,
		 *ciphertext,
		 *text;
   size_t blocks_required, text_len, packed_data_len, hmac_len;
   gcry_cipher_hd_t handle;
   gcry_mac_hd_t mac;
   gcry_error_t err;
   // here I really don't understand why they use if
   // in the original code they comment (fetch text to be encrypted)
   if (!(text_len = read_file_into_buf(infile, &text)))
   {
	   return 1;
   }

   // find number of blocks required for data
   // Maybe here is where I block for so long time

   blocks_required = text_len / AES256_BLOCK_SIZE;
   if (text_len % AES256_BLOCK_SIZE != 0)
   {
         blocks_required++;
   }
   // here we generate 128 byte salt in preparation for key derivation
   gcry_create_nonce(kdf_salt, KDF_SALT_SIZE);

   err = gcry_kdf_derive(password, strlen(password),
		   GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
		   kdf_salt, KDF_SALT_SIZE,KDF_ITERATIONS,
		   KDF_KEY_SIZE, kdf_key);

   if (err)
   {
       fprintf(stderr, "kdf_derive : %s/%s \n", gcry_strsource(err), gcry_strerror(err));
       free(text);
       return 1;
   }

   // copy the first 32 bytes of kdf key into aes key
   memcpy (aes_key, kdf_key, AES256_KEY_SIZE);

   // copy the last 32 bytes of kdf key into hmac key
   //memcpy (hmac_key, &(kdf_key[AES256_KEY_SIZE]),HMAC_KEY_SIZE);

   // Generate the initialisation vector
   gcry_create_nonce(init_vector, AES256_BLOCK_SIZE);


   // Begin encryption
   if (init_cipher(&handle, aes_key, init_vector))
   {
      free(text);
      return 1;
   }

   // make new buffer of size blocks required * AES256_BLOCK_SIZE for in place encryption
   ciphertext = malloc(blocks_required * AES256_BLOCK_SIZE);
   if (ciphertext == NULL)
   {
      fprintf(stderr,"Error : unable to allocate memory for the ciphertext\n");
      cleanup (handle,NULL,text,NULL,NULL);
      return 1;
   }

   memcpy(ciphertext, text, blocks_required * AES256_BLOCK_SIZE);
   free(text);

   // Encription is performed in-place
   err = gcry_cipher_encrypt(handle, ciphertext, AES256_BLOCK_SIZE * blocks_required, NULL, 0);
   if (err)
   {
      fprintf(stderr,"cipher_encrypt:%s/%s\n", gcry_strsource(err), gcry_strerror(err));
      cleanup(handle, NULL, ciphertext,NULL, NULL);
      return 1;
   }

   // Compute and allocate for packed data
   // hmac_len =  gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA512);
   packed_data_len = KDF_SALT_SIZE + AES256_BLOCK_SIZE + (AES256_BLOCK_SIZE * blocks_required);

   packed_data = malloc(packed_data_len);

   if (packed_data == NULL)
   {
      fprintf(stderr, "Unable to allocate memory for packed data\n");
      cleanup(handle,NULL,ciphertext,NULL,NULL);
      return 1;
   }

   // pack data before writing : salt::IV::ciphertext::HMAC where "::" denotes concatenation
   memcpy(packed_data,kdf_salt, KDF_SALT_SIZE);
   memcpy(&(packed_data[KDF_SALT_SIZE]), init_vector, AES256_BLOCK_SIZE);
   memcpy(&(packed_data[KDF_SALT_SIZE + AES256_BLOCK_SIZE]), ciphertext, AES256_BLOCK_SIZE * blocks_required);



   if (!write_buf_to_file(outfile,packed_data,packed_data_len))
   {
       printf("aucune ecriture nada !!!");
       cleanup(handle, mac, ciphertext, packed_data, hmac);
       return 1;
   }
}


int decrypt_file (char * infile, char *outfile, char * password)
{
     unsigned char init_vector[AES256_BLOCK_SIZE],
                   kdf_salt[KDF_SALT_SIZE],
		   kdf_key[KDF_KEY_SIZE],
		   aes_key[AES256_KEY_SIZE],
		   //hmac_key[HMAC_KEY_SIZE],
		   *hmac = NULL,
		   *packed_data = NULL,
		   *ciphertext;

     size_t blocks_required,ciphertext_len /*, packed_data_len,  hmac_len*/;
     gcry_cipher_hd_t handle;
     //gcry_mac_hd_t mac;
     gcry_error_t err;


     // key derivation: PBKDF2 using SHA512 w/ 128 byte salt over 10 iterations into a 64 byte key
     err = gcry_kdf_derive(password,
		           strlen(password),
			   GCRY_KDF_PBKDF2,
			   GCRY_MD_SHA512,
			   kdf_salt,
			   KDF_SALT_SIZE,
			   KDF_ITERATIONS,
			   KDF_KEY_SIZE,
			   kdf_key);
     if (err){
             fprintf( stderr,"kdf derive: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
	     cleanup(NULL, NULL, ciphertext, packed_data,hmac);
	     return 1;
     }

     // copy the first 32 bytes of kdf_key into aes_key
     memcpy(aes_key, kdf_key, AES256_KEY_SIZE);

    //  Copy the last 32 bytes of kdf_key into hmac_key
    //memcpy (hmac_key, &(kdf_key[AES256_KEY_SIZE]),HMAC_KEY_SIZE);

    // Begin decription
    if (init_cipher(&handle, aes_key, init_vector))
    {
       cleanup(handle, NULL, ciphertext, packed_data, hmac);
       return 1;
    }

    err = gcry_cipher_decrypt(handle, ciphertext, ciphertext_len, NULL, 0);
    if (err)
    {
       fprintf(stderr,"cipher_decrypt: %s /%s \n", gcry_strsource(err), gcry_strerror(err));
       cleanup(handle, NULL, ciphertext, packed_data, hmac);
       return 1;
    }

    // write plaintext to the output file
    if (!write_buf_to_file(outfile, ciphertext, ciphertext_len))
      fprintf(stderr, "0 bytes written. \n");

    cleanup(handle, NULL, ciphertext, packed_data, hmac);

    return 0;
    }


    void display_usage()
    {
    puts("Usage : ./encrypt_decrypt [encrypt | decrypt] <input file path > <output file path> <password>");
    }

    int main (int argc, const char **argv)
    {
    if (argc < 5)
    {
       fprintf(stderr,"Error: not enough arguments. \n");
       display_usage();
       return 1;
    }

    if (strncmp(argv[1],"encrypt", 7)==0){
       encrypt_file((char *)argv[2],(char *)argv[3], (char *)argv[4]);
    }
    else if (strncmp(argv[1],"decrypt", 7) == 0)
    {
            decrypt_file((char *) argv[2], (char *) argv[3], (char *) argv[4]);
    }
    else
    {
      fprintf(stderr, "Error : invalid action .\n");
      display_usage();
      return 1;
    }

    return 0;
    }

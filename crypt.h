/*
 * Cryptography functions
 *
 * WORK92107
 *
 * Copyright (C) 2015 WORK Microwave GmbH
 *
 * Author: Karl Krach <karl.krach@work-microwave.com>
 */



/** Extracts the content from a GPG signed file
  * @path    path to file
  * @content pointer to memory to write content to
  * @size    size of memory
  * @returns 0 on success, -1 on error
  */
int crypt_extract_signed_content(const char* path, const char** content, int size);

#ifndef __ID_BLOCKCHAIN_CRYPTO_TOOLS_H__
#define __ID_BLOCKCHAIN_CRYPTO_TOOLS_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/**
 * \fn void print_string_hex(const unsigned char *msg, size_t len)
 *
 * \brief Print in the standard output a string in hexadecimal
 *        form
 *
 * \param[in] msg message to print
 * \param[in] len length of the message msg
 */
void print_string_hex(const unsigned char *msg, size_t len);


#endif /* __ID_BLOCKCHAIN_CRYPTO_TOOLS_H__ */

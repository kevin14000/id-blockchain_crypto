/**
 * \file id_blockchain_crypto_tools.h
 *
 * \brief Header file for containing the definition of
 *        tools for this crypto library for the project
 *        ID-Blockchain.
 *
 * \auhtors Kevin Atighehchi <kevin.atighehchi@unicaen.fr>
 *          Morgan Barbier <morgan.barbier@ensicaen.fr>
 *
 * \version 1.0
 *
 * \date 2018-06-29
 */
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

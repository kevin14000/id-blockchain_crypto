/**
 * \file id_blockchain_hashing.h
 *
 * \brief Header file for containing definition of
 *        hash functions, that is SHA256 and SHA512.
 *
 * \auhtors Kevin Atighehchi <kevin.atighehchi@unicaen.fr>
 *          Morgan Barbier <morgan.barbier@ensicaen.fr>
 *
 * \version 1.0
 *
 * \date 2018-06-29
 */
#ifndef ID_BLOCKCHAIN_HASHING_H
#define ID_BLOCKCHAIN_HASHING_H

#include <openssl/sha.h>


/**
 * \fn void id_blockchain_sha256(const unsigned char *byte_string,
 *                               size_t len,
 *                               unsigned char digest[SHA256_DIGEST_LENGTH]);
 *
 * \brief Hash function of 256 output bits, for a security level of 128 bits
 *        (collision resilient). It takes three input parameters of which
 *        to write the result
 *
 * \param[in] byte_string is the byte string to hash
 * \param[in] len is the length of byte_string
 * \param[in] digest[] is the output of 32 bytes
*/
void id_blockchain_sha256(const unsigned char *byte_string,
			  size_t len,
			  unsigned char digest[SHA256_DIGEST_LENGTH]);

/**
 * \fn void id_blockchain_sha512(const unsigned char *byte_string,
 *                               size_t len,
 *                               unsigned char digest[SHA512_DIGEST_LENGTH]);
 *
 * \brief Hash function of 512 output bits, for a security level of 256 bits
 *        (collision resilient). It takes three input parameters of which
 *        to write the result
 *
 * \param[in] byte_string is the byte string to hash
 * \param[in] len is the length of byte_string
 * \param[in] digest[] is the output of 64 bytes
*/
void id_blockchain_sha512(const unsigned char *byte_string, 
			  size_t len,
			  unsigned char digest[SHA512_DIGEST_LENGTH]);

#endif /* ID_BLOCKCHAIN_HASHING_H */

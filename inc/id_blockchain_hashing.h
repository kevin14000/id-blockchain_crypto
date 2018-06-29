#ifndef ID_BLOCKCHAIN_HASHING_H
#define ID_BLOCKCHAIN_HASHING_H

#include <openssl/sha.h>


/* Fonction de hachage avec une sortie de 256 bits, pour un niveau de sécurité
   de 128 bits (résistance aux collisions). Elle prend trois paramètres dont 
   une sortie.
	 Entrées : Une chaîne d'octets (entièrement en mémoire)
	 					 La longueur de cette chaîne, en nombre d'octets
   Retour :  Le condensé en paramètre, une chaîne de 32 octets
*/
void id_blockchain_sha256(const unsigned char *byte_string, 
												  size_t len,
												  unsigned char digest[SHA256_DIGEST_LENGTH]);
												  
/* Fonction de hachage avec une sortie de 512 bits, pour un niveau de sécurité
   de 256 bits. Elle prend trois paramètres dont une sortie.
	 Entrées : Une chaîne d'octets (entièrement en mémoire)
	 					 La longueur de cette chaîne, en nombre d'octets
   Retour :  Le condensé en paramètre, une chaîne de 64 octets
*/
void id_blockchain_sha512(const unsigned char *byte_string, 
													size_t len,
													unsigned char digest[SHA512_DIGEST_LENGTH]);
																		
#endif

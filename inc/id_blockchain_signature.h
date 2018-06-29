#ifndef ID_BLOCKCHAIN_SIGNATURE_H
#define ID_BLOCKCHAIN_SIGNATURE_H

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

/* Définition d'un type "paire de clés" pour ECDSA */
typedef EC_KEY ID_BLOCKCHAIN_EC_KEY;

/* Définition d'un type "point" sur une courbe elliptique,
	 par ex. pour créer une clé publique pour ECDSA 
*/
typedef EC_POINT ID_BLOCKCHAIN_EC_POINT;

/* Définition d'un type "scalaire" pour une courbe elliptique,
   par ex. pour créer une clé privée pour ECDSA 
*/
typedef BIGNUM ID_BLOCKCHAIN_BIGNUM;

/* Définition d'un type pour une signature ECDSA */
typedef ECDSA_SIG ID_BLOCKCHAIN_ECDSA_SIG;

/* Fonction de génération de clés. Le cas d'usage est simplifié puisque
	 l'utilisateur ne gère pas le choix de la courbe.
	 Retourne une paire de clés pour ECDSA avec une courbe de niveau de sécurité 
   256 bits 
*/
ID_BLOCKCHAIN_EC_KEY *id_blockchain_ecdsa256_keygen(void);

/* Fonction de génération de clés. Le cas d'usage est simplifié puisque
	 l'utilisateur ne gère pas le choix de la courbe.
	 Retourne une paire de clés pour ECDSA avec une courbe de niveau de sécurité 
   d'au moins 512 bits 
*/
ID_BLOCKCHAIN_EC_KEY *id_blockchain_ecdsa521_keygen(void);

/* Libère l'espace mémoire alloué pour une paire de clés. 
   Prend en paramètre la paire de clés.
*/
void id_blockchain_eckey_free(ID_BLOCKCHAIN_EC_KEY *eckey);

/* Retourne la clé privée contenue dans une paire de clés.
   Entrée : La paire de clés
   Retour : La clé privée
*/
const ID_BLOCKCHAIN_BIGNUM *id_blockchain_ec_get_private_key
														(const ID_BLOCKCHAIN_EC_KEY *eckey);
														
/* Retourne la clé publique contenue dans une paire de clés.
   Entrée : La paire de clés
   Retour : La clé publique
*/
const ID_BLOCKCHAIN_EC_POINT *id_blockchain_ec_get_public_key
														(const ID_BLOCKCHAIN_EC_KEY *eckey);
														
/* (Ré)initialise la clé privée d'une paire de clés 
	 Entrées : La paire de clés
	 					 La clé privée à assigner
	 Sortie : un entier, 1 en cas de succès et 0 en cas d'erreur
*/
int id_blockchain_ec_set_private_key(ID_BLOCKCHAIN_EC_KEY *eckey, 
																		 const ID_BLOCKCHAIN_BIGNUM *prv);
																		 
/* (Ré)initialise la clé publique d'une paire de clés 
	 Entrées : La paire de clés
	 					 La clé publique à assigner
	 Sortie : une entier, 1 en cas de succès et 0 en cas d'erreur
*/
int id_blockchain_ec_set_public_key(ID_BLOCKCHAIN_EC_KEY *eckey, 
																		const ID_BLOCKCHAIN_EC_POINT *pub);
																		
/* Génère une signature ECDSA de niveau de sécurité 128 bits.
	 Entrées : Une chaîne d'octets à sifgner
	 					 La longueur de cette chaîne
	 					 Une paire de clé entièrement initialisée (au moins la clé privée), 
	 					 avec un niveau de sécurité de 128 bits
	 Sortie :  La signature
*/
ID_BLOCKCHAIN_ECDSA_SIG* id_blockchain_ecdsa256_do_sign
												 (const unsigned char *msg, 
												  size_t len,
                          ID_BLOCKCHAIN_EC_KEY *eckey);
                          
/* Génère une signature ECDSA de niveau de sécurité 256 bits.
	 Entrées : Une chaîne d'octets à signer
	 					 La longueur de cette chaîne
	 					 Une paire de clés entièrement initialisée (au moins la clé privée), 
	 					 avec un niveau de sécurité de 256 bits
	 Sortie :  La signature
*/
ID_BLOCKCHAIN_ECDSA_SIG* id_blockchain_ecdsa521_do_sign
												 (const unsigned char *msg, 
												  size_t len,
                          ID_BLOCKCHAIN_EC_KEY *eckey);
                          
/* Vérifie une signature ECDSA de niveau de sécurité 128 bits.
	 Entrées : Une chaîne d'octets
	 					 La longueur de cette chaîne
	 					 La signature de cette chaîne d'octets
	 					 Une paire de clés entièrement initialisée (au moins la clé publique)
	 					 avec un niveau de sécurité de 128 bits
	 Sortie :  -1 si erreur
	 					 0  si signature incorrecte
	 					 1  si signature valide
*/
int id_blockchain_ecdsa256_do_verify(const unsigned char *msg, size_t len,
                    								 const ID_BLOCKCHAIN_ECDSA_SIG *sig, 
                    								 ID_BLOCKCHAIN_EC_KEY* eckey);
                    								 
/* Vérifie une signature ECDSA de niveau de sécurité 256 bits.
	 Entrées : Une chaîne d'octets
	 					 La longueur de cette chaîne
	 					 La signature de cette chaîne d'octets
	 					 Une paire de clés entièrement initialisée (au moins la clé publique)
	 					 avec un niveau de sécurité de 256 bits
	 Sortie :  -1 si erreur
	 					 0  si signature incorrecte
	 					 1  si signature valide
*/
int id_blockchain_ecdsa521_do_verify(const unsigned char *msg, size_t len,
                    								 const ID_BLOCKCHAIN_ECDSA_SIG *sig, 
                    								 ID_BLOCKCHAIN_EC_KEY* eckey);
                    								 
/* Impression d'une chaîne d'octets en hexa.
	 Entrées : Une chaîne d'octets
	 				   La longueur 
*/
void print_string_hex(const unsigned char *msg, size_t len);

/* Désallocation d'une signature.
	 Entrée : La signature
*/
void id_blockchain_ecdsa_sig_free(ID_BLOCKCHAIN_ECDSA_SIG *sig);

#endif


/*-
 * Copyright (c) 1997        Gabor Kincses <gabor@acm.org>
 *               1997 - 2001 Brian Somers <brian@Awfulhak.org>
 *          based on work by Eric Rosenquist
 *                           Strata Software Limited.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/usr.sbin/ppp/chap_ms.c,v 1.9.2.6 2002/09/01 02:12:23 brian Exp $
 *
 *  See : http://tools.ietf.org/html/rfc2759
 */
#include "system.h"

#ifdef HAVE_OPENSSL

#include <openssl/evp.h>
#include <openssl/des.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

/*
 * MS-CHAP (CHAP80)	rfc2433
 * MS-CHAP-V2 (CHAP81)	rfc2759
 * MPPE key management	draft-ietf-pppext-mppe-keys-02.txt
 */

static char SHA1_Pad1[40] = {0}; // All zeros
static char SHA1_Pad2[40] =
{0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2};

static u_char
Get7Bits(u_char *input, int startBit)
{
  register unsigned int word;
  word  = (unsigned)input[startBit / 8] << 8;
  word |= (unsigned)input[startBit / 8 + 1];
  word >>= 15 - (startBit % 8 + 7);
  return word & 0xFE;
}

static void
MakeKey(u_char *key, u_char *des_key)
{
  des_key[0] = Get7Bits(key,  0);
  des_key[1] = Get7Bits(key,  7);
  des_key[2] = Get7Bits(key, 14);
  des_key[3] = Get7Bits(key, 21);
  des_key[4] = Get7Bits(key, 28);
  des_key[5] = Get7Bits(key, 35);
  des_key[6] = Get7Bits(key, 42);
  des_key[7] = Get7Bits(key, 49);

  DES_set_odd_parity((DES_cblock *)des_key);
}

static void
DesEncrypt(u_char *clear, u_char *key, u_char *cipher)
{
  u_char des_key[8];
  int outlen;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  MakeKey(key, des_key);

  EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, des_key, NULL);
  EVP_CIPHER_CTX_set_padding(ctx, 0); // สำคัญมาก: MS-CHAP ไม่ใช้ Padding

  EVP_EncryptUpdate(ctx, cipher, &outlen, clear, 8);
  EVP_EncryptFinal_ex(ctx, cipher + outlen, &outlen);

  EVP_CIPHER_CTX_free(ctx);
}

u_char *to_unicode(u_char *non_uni) {
  u_char *retUni;
  int i, len = strlen((char *)non_uni);

  retUni = (u_char *)calloc(1, (len + 1) * 2);
  if (!retUni) return NULL;

  for (i = 0; i < len; i++) {
    retUni[(2 * i)] = non_uni[i];
  }
  return retUni;
}

void
NtPasswordHash(u_char *Password, int len, u_char *hash)
{
  if (!Password) return;
  u_char *uniPassword = to_unicode(Password);
  unsigned int hashLen;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  EVP_DigestInit_ex(ctx, EVP_md4(), NULL);
  EVP_DigestUpdate(ctx, uniPassword, len * 2);
  EVP_DigestFinal_ex(ctx, hash, &hashLen);

  EVP_MD_CTX_free(ctx);
  free(uniPassword);
}

void
HashNtPasswordHash(u_char *hash, u_char *hashhash)
{
  unsigned int hashLen;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  EVP_DigestInit_ex(ctx, EVP_md4(), NULL);
  EVP_DigestUpdate(ctx, hash, 16);
  EVP_DigestFinal_ex(ctx, hashhash, &hashLen);

  EVP_MD_CTX_free(ctx);
}

void
ChallengeHash(u_char *PeerChallenge, u_char *AuthenticatorChallenge,
              u_char *UserName, int UserNameLen, u_char *Challenge)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  u_char Digest[20]; // SHA1 length
  u_char *Name;

  Name = (u_char *)strrchr((char *)UserName, '\\');
  if (NULL == Name) Name = UserName;
  else Name++;

  EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
  EVP_DigestUpdate(ctx, PeerChallenge, 16);
  EVP_DigestUpdate(ctx, AuthenticatorChallenge, 16);
  EVP_DigestUpdate(ctx, Name, strlen((char *)Name));
  EVP_DigestFinal_ex(ctx, Digest, NULL);

  memcpy(Challenge, Digest, 8);
  EVP_MD_CTX_free(ctx);
}

static void
ChallengeResponse(u_char *challenge, u_char *pwHash, u_char *response)
{
  u_char ZPasswordHash[21];
  memset(ZPasswordHash, '\0', sizeof ZPasswordHash);
  memcpy(ZPasswordHash, pwHash, 16);

  DesEncrypt(challenge, ZPasswordHash + 0, response + 0);
  DesEncrypt(challenge, ZPasswordHash + 7, response + 8);
  DesEncrypt(challenge, ZPasswordHash + 14, response + 16);
}

void
GenerateNTResponse(u_char *AuthenticatorChallenge, u_char *PeerChallenge,
                   u_char *UserName, int UserNameLen,
                   u_char *Password, int PasswordLen, u_char *Response)
{
  u_char Challenge[8];
  u_char PasswordHash[16];

  ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName, UserNameLen, Challenge);
  NtPasswordHash(Password, PasswordLen, PasswordHash);
  ChallengeResponse(Challenge, PasswordHash, Response);
}

void
GenerateAuthenticatorResponse(u_char *Password, int PasswordLen,
                              u_char *NTResponse, u_char *PeerChallenge,
                              u_char *AuthenticatorChallenge, u_char *UserName,
                              int UserNameLen, u_char *AuthenticatorResponse)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  u_char PasswordHash[16], PasswordHashHash[16];
  u_char Challenge[8], Digest[20];
  int i;

  u_char Magic1[39] = "Magic server to client signing constant";
  u_char Magic2[41] = "Pad to make it do more than one iteration";

  NtPasswordHash(Password, PasswordLen, PasswordHash);
  HashNtPasswordHash(PasswordHash, PasswordHashHash);

  EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
  EVP_DigestUpdate(ctx, PasswordHashHash, 16);
  EVP_DigestUpdate(ctx, NTResponse, 24);
  EVP_DigestUpdate(ctx, Magic1, 39);
  EVP_DigestFinal_ex(ctx, Digest, NULL);

  ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName, UserNameLen, Challenge);

  EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
  EVP_DigestUpdate(ctx, Digest, 20);
  EVP_DigestUpdate(ctx, Challenge, 8);
  EVP_DigestUpdate(ctx, Magic2, 41);
  EVP_DigestFinal_ex(ctx, Digest, NULL);

  AuthenticatorResponse[0] = 'S';
  AuthenticatorResponse[1] = '=';
  for (i = 0; i < 20; i++) {
    sprintf((char *)AuthenticatorResponse + 2 + i * 2, "%02X", Digest[i]);
  }

  EVP_MD_CTX_free(ctx);
}

void
GetMasterKey(char *PasswordHashHash, char *NTResponse, char *MasterKey)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  u_char Digest[20];
  u_char Magic1[27] = "This is the MPPE Master Key";

  EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
  EVP_DigestUpdate(ctx, (u_char *)PasswordHashHash, 16);
  EVP_DigestUpdate(ctx, (u_char *)NTResponse, 24);
  EVP_DigestUpdate(ctx, Magic1, 27);
  EVP_DigestFinal_ex(ctx, Digest, NULL);

  memcpy(MasterKey, Digest, 16);
  EVP_MD_CTX_free(ctx);
}

void
GetAsymetricStartKey(char *MasterKey, char *SessionKey, int SessionKeyLength,
                     int IsSend, int IsServer)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  u_char Digest[20];
  u_char *s;

  static u_char Magic2[84] = "On the client side, this is the send key; on the server side, it is the receive key.";
  static u_char Magic3[84] = "On the client side, this is the receive key; on the server side, it is the send key.";

  s = (IsSend == IsServer) ? Magic3 : Magic2;

  EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
  EVP_DigestUpdate(ctx, (u_char *)MasterKey, 16);
  EVP_DigestUpdate(ctx, SHA1_Pad1, 40);
  EVP_DigestUpdate(ctx, s, 84);
  EVP_DigestUpdate(ctx, SHA1_Pad2, 40);
  EVP_DigestFinal_ex(ctx, Digest, NULL);

  memcpy(SessionKey, Digest, SessionKeyLength);
  EVP_MD_CTX_free(ctx);
}

void
GetNewKeyFromSHA(char *StartKey, char *SessionKey, long SessionKeyLength,
                 char *InterimKey)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  u_char Digest[20];

  EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
  EVP_DigestUpdate(ctx, (u_char *)StartKey, SessionKeyLength);
  EVP_DigestUpdate(ctx, SHA1_Pad1, 40);
  EVP_DigestUpdate(ctx, (u_char *)SessionKey, SessionKeyLength);
  EVP_DigestUpdate(ctx, SHA1_Pad2, 40);
  EVP_DigestFinal_ex(ctx, Digest, NULL);

  memcpy(InterimKey, Digest, SessionKeyLength);
  EVP_MD_CTX_free(ctx);
}

void
mschap_NT(u_char *passwordHash, u_char *challenge)
{
  u_char response[24] = "";
  ChallengeResponse(challenge, passwordHash, response);
  memcpy(passwordHash, response, 24);
  passwordHash[24] = 1; 
}

void
mschap_LANMan(u_char *digest, u_char *challenge, char *secret)
{
  u_char salt[] = "KGS!@#$%";
  u_char SECRET[14] = {0}, hash[16] = {0};
  int i;

  for (i = 0; secret[i] && i < 14; i++)
    SECRET[i] = toupper(secret[i]);

  DesEncrypt(salt, SECRET, hash);
  DesEncrypt(salt, SECRET + 7, hash + 8);
  ChallengeResponse(challenge, hash, digest);
}

#endif

---
title: Use of Hybrid Public-Key Encryption (HPKE) with CBOR Object Signing and Encryption (COSE)
abbrev: COSE HPKE
docname: draft-ietf-cose-hpke-03
category: std

ipr: pre5378Trust200902
area: Security
workgroup: COSE
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
       ins: H. Tschofenig
       name: Hannes Tschofenig
       organization: Arm Limited
       email: hannes.tschofenig@arm.com

 -
      ins: B. Moran
      name: Brendan Moran
      organization: Arm Limited
      email: Brendan.Moran@arm.com


normative:
  RFC2119:
  RFC8174:
  RFC9180:
  RFC8152:
  
informative:
  RFC8937:
  RFC2630:
  
--- abstract

This specification defines hybrid public-key encryption (HPKE) for use with 
CBOR Object Signing and Encryption (COSE). HPKE offers a variant of
public-key encryption of arbitrary-sized plaintexts for a recipient public key.

HPKE works for any combination of an asymmetric key encapsulation mechanism (KEM),
key derivation function (KDF), and authenticated encryption with
additional data (AEAD) encryption function. Authentication for HPKE in COSE is
provided by COSE-native security mechanisms.

--- middle

#  Introduction

Hybrid public-key encryption (HPKE) {{RFC9180}} is a scheme that 
provides public key encryption of arbitrary-sized plaintexts given a 
recipient's public key. HPKE utilizes a non-interactive ephemeral-static 
Diffie-Hellman exchange to establish a shared secret. The motivation for
standardizing a public key encryption scheme is explained in the introduction
of {{RFC9180}}.

The HPKE specification defines several features for use with public key encryption
and a subset of those features is applied to COSE {{RFC8152}}. Since COSE provides
constructs for authentication, those are not re-used from the HPKE specification.
This specification uses the "base" mode, as it is called in HPKE specification
language.

# Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP&nbsp;14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

This specification uses the following abbreviations and terms:
- Content-encryption key (CEK), a term defined in CMS {{RFC2630}}.
- Hybrid Public Key Encryption (HPKE) is defined in {{RFC9180}}.
- pkR is the public key of the recipient, as defined in {{RFC9180}}.
- skR is the private key of the recipient, as defined in {{RFC9180}}.

# HPKE for COSE

## Overview

This specification supports two uses of HPKE in COSE, namely 

* HPKE in a single sender - single recipient setup.
  This use cases uses a one layer structure for efficiency. 
  {{one-layer}} provides the details.

* HPKE in a single sender - multiple recipient setup. 
  This use case requires a two layer structure.  {{two-layer}} 
  provides the details.

HPKE in "base" mode requires little information to be exchanged between 
a sender and a recipient, namely

* algorithm information, 
* the ephemeral public key, and 
* an identifier of the static recipient key.

In the subsections below we explain how this information is carried
inside the COSE_Encrypt0 and the COSE_Encrypt for the one layer and the
two layer structure, respectively.

In both cases a new structure is used to convey information about the HPKE
sender, namely the HPKE Sender Information structure (COSE_HPKE_Sender).

The CDDL grammar describing COSE_HPKE_Sender is:

~~~
   COSE_HPKE_Sender = [
       kdf_id : uint,           ; kdf id
       aead_id : uint,          ; aead id
       enc : bstr,              ; enc
       ? kem_id : uint,         ; kem id
   ]
~~~

~~~
   +---------+----------------+------------+-------------------+
   | Name    | CBOR Type      | Value      | Description       |
   |         |                | Registry   |                   |
   +---------+----------------+------------+-------------------+
   | kdf_id  | uint           | HPKE KDF   | Identifiers for   |
   |         |                | IDs        | KDF IDs           |
   |         |                |            |                   |
   | aead_id | uint           | HPKE AEAD  | Identifiers for   |
   |         |                | IDs        | AEAD IDs          |
   |         |                |            |                   |
   | enc     | bstr           |            | Encapsulated key  |
   |         |                |            | defined by HPKE   |
   |         |                |            |                   |
   | kem_id  | uint           | HPKE       | Identifiers for   |
   |         |                | KEM IDs    | the Key           |
   |         |                | Registry   | Encapsulation     |
   |         |                |            | Mechanisms        |
   |         |                |            |                   |
   +---------+----------------+------------+-------------------+
~~~
{: #table-hpke-sender title="COSE_HPKE_Sender Labels"}

   kdf_id: This parameter contains the Key Derivation Functions (KDF)
      identifier. The registry containing the KDF ids has been established 
      with RFC 9180. The cipher id parameter MUST be present in the 
      COSE_HPKE_Sender structure.

   aead_id: This parameter contains the Authenticated Encryption with
      Associated Data (AEAD) identifiers. The registry containing the 
      AEAD ids has been established with RFC 9180. The cipher id 
      parameter MUST be present in the COSE_HPKE_Sender structure.

   enc: This parameter contains the encapsulated key, which is output
      of the HPKE KEM. The enc parameter MUST be present in the 
      COSE_HPKE_Sender structure.

 kem_id:  This parameter is used to identify the Key Encapsulation
       Mechanisms (KEM). The registry for KEMs has been established
       with RFC 9180. This parameter is optional since the kid may be
       used to determine the KEM.

### One Layer Structure {#one-layer}

With the one layer structure the information carried inside the 
COSE_recipient structure is embedded inside the COSE_Encrypt0. 

HPKE is used to directly encrypt the plaintext. The resulting ciphertext
may be included in the COSE_Encrypt0 or may be detached.

A sender MUST set the alg parameter in the protected header, which
indicates the use of HPKE. 

The sender MUST place the kid and the HPKE sender information structure
into the unprotected header. 

{{cddl-hpke-one-layer}} shows the COSE_Encrypt0 CDDL structure.

~~~
COSE_Encrypt0_Tagged = #6.16(COSE_Encrypt0)

; Layer 0
COSE_Encrypt0 = [
    Headers,
    ciphertext : bstr / nil,
]
~~~
{: #cddl-hpke-one-layer title="CDDL for HPKE-based COSE_Encrypt0 Structure"}

The COSE_Encrypt0 MAY be tagged or untagged.

An example is shown in {{one-layer-example}}.

### Two Layer Structure {#two-layer}

With the two layer structure the HPKE information is conveyed in the COSE_recipient structure, i.e. one
COSE_recipient structure per recipient. 

In this approach the following layers are involved: 

- Layer 0 (corresponding to the COSE_Encrypt structure) contains content (plaintext)
encrypted with the CEK. This ciphertext may be detached. If not detached, then
it is included in the COSE_Encrypt structure.

- Layer 1 (corresponding to a recipient structure) contains parameters needed for 
HPKE to generate a shared secret used to encrypt the CEK. This layer conveys the 
encrypted CEK in the encCEK structure. The protected header MUST contain the algorithm
information and the unprotected header MUST contain the HPKE sender information structure
and the key id (kid) of the static recipient public key.

This two-layer structure is used to encrypt content that can also be shared with
multiple parties at the expense of a single additional encryption operation.
As stated above, the specification uses a CEK to encrypt the content at layer 0.
For example, the content encrypted at layer 0 is a firmware image.  The
same ciphertext firmware image is processed by all of the recipients;
however, each recipient uses their own private key to obtain the CEK.

The COSE_recipient structure shown in {{cddl-hpke}} is repeated for each
recipient.

~~~
COSE_Encrypt_Tagged = #6.96(COSE_Encrypt)
 
/ Layer 0 /
COSE_Encrypt = [
  Headers,
  ciphertext : bstr / nil,
  recipients : + COSE_recipient
]

/ Layer 1 /
COSE_recipient = [
  protected   : bstr .cbor header_map,
  unprotected : header_map,
  encCEK      : bstr,
]

header_map = {
  Generic_Headers,
  * label => values,
}
~~~
{: #cddl-hpke title="CDDL for HPKE-based COSE_Encrypt Structure"}

The COSE_Encrypt MAY be tagged or untagged. 

An example is shown in {{two-layer-example}}.

## HPKE Encryption with SealBase

The SealBase(pkR, info, aad, pt) function is used to encrypt a plaintext pt to
a recipient's public key (pkR).

IMPORTANT: For use in COSE_Encrypt, the plaintext "pt" passed into the 
SealBase is the CEK. The CEK is a random byte sequence of length 
appropriate for the encryption algorithm selected in layer 0. For 
example, AES-128-GCM requires a 16 byte key and the CEK would 
therefore be 16 bytes long. In case of COSE_Encrypt0, the plaintext 
"pt" passed into the SealBase is the raw plaintext.

The "info" parameter can be used to influence the generation of keys and the
"aad" parameter provides additional authenticated data to the AEAD algorithm
in use. This specification does not mandate the use of the info and the aad
parameters.

If SealBase() is successful, it will output a ciphertext "ct" and an encapsulated
key "enc".

The content of the info parameter is based on the 'COSE_KDF_Context' structure,
which is detailed in {{cddl-cose-kdf}}.

## HPKE Decryption with OpenBase

The recipient will use the OpenBase(enc, skR, info, aad, ct) function with the enc and
ct parameters received from the sender. The "aad" and the "info" parameters are obtained
via the context of the usage.

The OpenBase function will, if successful, decrypt "ct". When decrypted, the result
will be either the CEK (if using COSE_Encrypt), or the raw plaintext (if using 
COSE_Encrypt0). The CEK is the symmetric key used to decrypt the ciphertext in 
layer 0 of the COSE_Encrypt structure.

## Info Structure

This section provides a suggestion for constructing the info structure, when used with
SealBase() and OpenBase(). Note that the use of the aad and the info structures for these
two functions is optional. Profiles of this specification may require their use and may
define different info structure.

This specification re-uses the context information structure defined in
{{RFC8152}} as a foundation for the info structure. This payload becomes the content
of the info parameter for the HPKE functions, when utilized. For better readability of
this specification the COSE_KDF_Context structure is repeated in {{cddl-cose-kdf}}.

~~~
   PartyInfo = (
       identity : bstr / nil,
       nonce : bstr / int / nil,
       other : bstr / nil
   )

   COSE_KDF_Context = [
       AlgorithmID : int / tstr,
       PartyUInfo : [ PartyInfo ],
       PartyVInfo : [ PartyInfo ],
       SuppPubInfo : [
           keyDataLength : uint,
           protected : empty_or_serialized_map,
           ? other : bstr
       ],
       ? SuppPrivInfo : bstr
   ]
~~~
{: #cddl-cose-kdf title="COSE_KDF_Context Data Structure for info parameter"}

The fields in {{cddl-cose-kdf}} are populated as follows:

- PartyUInfo.identity corresponds to the kid found in the
COSE_Sign_Tagged or COSE_Sign1_Tagged structure (when a digital
signature is used). When utilizing a MAC, then the kid is found in
the COSE_Mac_Tagged or COSE_Mac0_Tagged structure.

- PartyVInfo.identity corresponds to the kid used for the respective
recipient from the inner-most recipients array.

- The value in the AlgorithmID field corresponds to the alg parameter
in the unprotected header structure of the recipient structure.

- keyDataLength is set to the number of bits of the desired output value.

- protected refers to the protected structure of the inner-most array.

# Examples

## One Layer {#one-layer-example}

An example of the COSE_Encrypt0 structure using the HPKE scheme is
shown in {{hpke-example-one}}. Line breaks and comments have been inserted
for better readability. It uses the following algorithm combination: The
key encapsulation mechanism DHKEM(P-256, HKDF-SHA256) with AES-128-GCM 
(as the AEAD) and HKDF-SHA256 as the KDF is used.

~~~
// Example of COSE-HPKE (Encrypt0)
// payload: "This is the content", aad: ""
// 
16([
    h'a10120',  // alg = HPKE (-1)
    {
        4: h'3031', // kid
        -4: {       // HPKE sender information
            1: 16,  // kem = DHKEM(P-256, HKDF-SHA256)
            5: 1,   // kdf = HKDF-SHA256
            2: 1,   // aead = AES-128-GCM
            3: h'048c6f75e463a773082f3cb0d3a701348a578c67
                 80aba658646682a9af7291dfc277ec93c3d58707
                 818286c1097825457338dc3dcaff367e2951342e
                 9db30dc0e7',  // enc
        },
    },
    / encrypted plaintext /
    h'ee22206308e478c279b94bb071f3a5fbbac412a6effe34195f7
      c4169d7d8e81666d8be13',
])
~~~
{: #hpke-example-one title="COSE_Encrypt0 Example for HPKE"}

## Two Layer {#two-layer-example}

An example of the COSE_Encrypt structure using the HPKE scheme is
shown in {{hpke-example-two}}. Line breaks and comments have been inserted
for better readability. It uses the following algorithm
combination: 

- At layer 0 AES-GCM-128 is used for encryption of the detached ciphertext.
- At the recipient structure at layer 1, the key encapsulation mechanism 
  DHKEM(P-256, HKDF-SHA256) with AES-128-GCM (as the AEAD) and HKDF-SHA256
  as the KDF is used.

The algorithm selection is based on the registry of the values offered
by the alg parameters (see {{IANA}}).

~~~
// Example of COSE-HPKE (Encrypt)
// plaintext: "This is the content.", aad: ""
96_0([
    h'a10120',  // alg = HPKE  (-1 #T.B.D.)
    {},         // protected header
    h'',        // detached plaintext
    [
        [
            h'a10120',  // alg = HPKE
            {
                4: h'3031', // kid
                -4: {       // HPKE sender information
                    1: 16,  // kem = DHKEM(P-256, HKDF-SHA256)
                    5: 1,   // kdf = HKDF-SHA256
                    2: 1,   // aead = AES-128-GCM
                    / enc output /
                    3: h'0421ccd1b00dd958d77e10399c
                         97530fcbb91a1dc71cb3bf41d9
                         9fd39f22918505c973816ecbca
                         6de507c4073d05cceff73e0d35
                         f60e2373e09a9433be9e95e53c',
                },
            },
            // ciphertext containing encrypted CEK
            h'bb2f1433546c55fb38d6f23f5cd95e1d72eb4
              c129b99a165cd5a28bd75859c10939b7e4d',
        ],
    ],
])
~~~
{: #hpke-example-two title="COSE_Encrypt Example for HPKE"}

To offer authentication of the sender the payload in {{hpke-example-two}}
is signed with a COSE_Sign1 wrapper, which is shown in {{hpke-example-sign}}.
The payload in {{hpke-example-sign}} corresponds to the content shown in
{{hpke-example-two}}.

~~~
18(
  [
    / protected / h'a10126' / {
            \ alg \ 1:-7 \ ECDSA 256 \
          } / ,
    / unprotected / {
          / kid / 4:'sender@example.com'
        },
    / payload /     h'AA19...B80C',
    / signature /   h'E3B8...25B8'
  ]
)
~~~
{: #hpke-example-sign title="COSE_Encrypt Example for HPKE"}


# Security Considerations {#sec-cons}

This specification is based on HPKE and the security considerations of HPKE
{{RFC9180}} are therefore applicable also to this specification.

HPKE assumes the sender is in possession of the public key of the recipient and
HPKE COSE makes the same assumptions. Hence, some form of public key distribution
mechanism is assumed to exist.

HPKE relies on a source of randomness to be available on the device. Additionally, 
with the two layer structure the CEK is randomly generated and the it MUST be
ensured that the guidelines for random number generations are followed. 

The COSE_Encrypt structure MUST be authenticated using COSE constructs like 
COSE_Sign, COSE_Sign1, COSE_MAC, or COSE_MAC0.

When COSE_Encrypt or COSE_Encrypt0 is used with a detached ciphertext then the
subsequently applied integrity protection via COSE_Sign, COSE_Sign1, COSE_MAC, 
or COSE_MAC0 does not cover this detached ciphertext. Implementers MUST ensure
that the detached ciphertext also experiences integrity protection. This is, for
example, the case when an AEAD cipher is used to produce the detached ciphertext
but may not be guaranteed by non-AEAD ciphers.

#  IANA Considerations {#IANA}

This document requests IANA to add new values to the COSE Algorithms registry
and to the COSE Header Algorithm Parameters registry, defined in {{RFC8152}} 
(in the Standards Action With Expert Review category).

## COSE Algorithms Registry

-  Name: HPKE
-  Value: TBD1 (Assumed: -1)
-  Description: HPKE for use with COSE
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

## COSE Header Algorithm Parameters

-  Name: encapsulated_key
-  Label: TBD2 (Assumed: -4)
-  Value type: bstr / [*any] / {* any => any }
-  Value Registry: N/A
-  Description: Encapsulated key for KEM-like algorithms

--- back

# Contributors

We would like thank the following individuals for their contributions
to the design of embedding the HPKE output into the COSE structure following 
a long and lively mailing list discussion. 

- Daisuke Ajitomi
- Ilari Liusvaara
- Richard Barnes

Finally, we would like to thank Russ Housley for his contributions to
the draft as a co-author of initial versions of the draft.

# Acknowledgements

We would like to thank Goeran Selander, Orie Steele, Mike Prorock, Michael Richardson, and John Mattsson for their review feedback.

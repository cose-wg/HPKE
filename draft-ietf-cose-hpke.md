---
title: Use of Hybrid Public-Key Encryption (HPKE) with CBOR Object Signing and Encryption (COSE)
abbrev: COSE HPKE
docname: draft-ietf-cose-hpke-06
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
  organization:
  email: hannes.tschofenig@gmx.net
  country: Austria
-
  ins: O. Steele
  name: Orie Steele
  role: editor
  organization: Transmute
  email: orie@transmute.industries
  country: United States
-
  ins: D. Ajitomi
  name: Daisuke Ajitomi
  organization:
  email: dajiaji@gmail.com
  country: Japan
-
  ins: L. Lundblade
  name: Laurence Lundblade
  organization: Security Theory LLC
  email: lgl@securitytheory.com
  country: United States

normative:
  RFC2119:
  RFC8174:
  RFC9180:
  RFC9052:
  RFC9053:
  
informative:
  RFC8937:
  RFC2630:
  HPKE-IANA:
     author:
        org: IANA
     title: Hybrid Public Key Encryption (HPKE) IANA Registry
     target: https://www.iana.org/assignments/hpke/hpke.xhtml
     date: October 2023
  
--- abstract

This specification defines hybrid public-key encryption (HPKE) for use with 
CBOR Object Signing and Encryption (COSE). HPKE offers a variant of
public-key encryption of arbitrary-sized plaintexts for a recipient public key.

HPKE works for any combination of an asymmetric key encapsulation mechanism (KEM),
key derivation function (KDF), and authenticated encryption with
additional data (AEAD) function. Authentication for HPKE in COSE is
provided by COSE-native security mechanisms or by one of the authenticated
variants of HPKE.

This document defines the use of the HPKE with COSE.

--- middle

#  Introduction

Hybrid public-key encryption (HPKE) {{RFC9180}} is a scheme that 
provides public key encryption of arbitrary-sized plaintexts given a 
recipient's public key. HPKE utilizes a non-interactive ephemeral-static 
Diffie-Hellman exchange to establish a shared secret. The motivation for
standardizing a public key encryption scheme is explained in the introduction
of {{RFC9180}}.

The HPKE specification provides a variant of public key encryption of
arbitrary-sized plaintexts for a recipient public key. It also
includes three authenticated variants, including one that authenticates
possession of a pre-shared key, one that authenticates possession of
a key encapsulation mechanism (KEM) private key, and one that
authenticates possession of both a pre-shared key and a KEM private key.

This specification utilizes HPKE as a foundational building block and
carries the output to COSE ({{RFC9052}}, {{RFC9053}}).

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
- Key Encapsulation Mechanism (KEM), see {{RFC9180}}.
- Key Derivation Function (KDF), see {{RFC9180}}.
- Authenticated Encryption with Associated Data (AEAD), see {{RFC9180}}.
- Additional Authenticated Data (AAD), see {{RFC9180}}.

# HPKE for COSE

## Overview

This specification supports two uses of HPKE in COSE, namely 

* HPKE in a single recipient setup.
  This use case utilizes a one layer COSE structure. 
  {{one-layer}} provides the details.

* HPKE in a multiple recipient setup. 
  This use case requires a two layer COSE structure.  {{two-layer}} 
  provides the details. While it is possible to support the single 
  recipient use case with a two layer structure, the single 
  layer setup is more efficient.

In both cases a new COSE header parameter, called 'encapsulated_key',
is used to convey the content of the enc structure defined in the HPKE
specification. "Enc" represents the serialized public key.

For use with HPKE the 'encapsulated_key' header parameter MUST
be present in the unprotected header parameter and MUST contain
the encapsulated key, which is output of the HPKE KEM, and it
is a bstr.

### Single Recipient / One Layer Structure {#one-layer}

With the one layer structure the information carried inside the 
COSE_recipient structure is embedded inside the COSE_Encrypt0. 

HPKE is used to directly encrypt the plaintext and the resulting ciphertext
is either included in the COSE_Encrypt0 or is detached. If a payload is
transported separately then it is called "detached content". A nil CBOR
object is placed in the location of the ciphertext. See Section 5
of {{RFC9052}} for a description of detached payloads.

The sender MUST set the alg parameter in the protected header, which
indicates the use of HPKE.

The sender MUST place the 'encapsulated_key' parameter into the unprotected
header. Although the use of the 'kid' parameter in COSE_Encrypt0 is
discouraged by RFC 9052, this profile allows the use of the 'kid' parameter
(or other parameters) to identify the static recipient public key used by
the sender. If the COSE_Encrypt0 contains the 'kid' then the recipient may
use it to select the appropriate private key.

HPKE defines an API and this API uses an "aad" parameter as input. When
COSE_Encrypt0 is used then there is no AEAD function executed by COSE
natively and HPKE offers this functionality.

The "aad" parameter provided to the HPKE API is constructed
as follows (and the design has been re-used from the COSE spec):

~~~
Enc_structure = [
    context : "Encrypt0",
    protected : empty_or_serialized_map,
    external_aad : bstr
]
~~~

The protected field in the Enc_structure contains the protected attributes 
from the COSE_Encrypt0 structure at layer 0, encoded in a bstr type.

The external_aad field in the Enc_structure contains the Externally Supplied
Data described in Section 4.3 and Section 5.3 in RFC 9052. If this field is
not supplied, it defaults to a zero-length byte string.

The HPKE APIs also use an "info" parameter as input and the details are
provided in {{info}}.

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

### Multiple Recipients / Two Layer Structure {#two-layer}

With the two layer structure the HPKE information is conveyed in the COSE_recipient 
structure, i.e. one COSE_recipient structure per recipient.

In this approach the following layers are involved: 

- Layer 0 (corresponding to the COSE_Encrypt structure) contains the content (plaintext)
encrypted with the CEK. This ciphertext MAY be detached. If not detached, then
it is included in the COSE_Encrypt structure.

- Layer 1 (corresponding to a recipient structure) contains parameters needed for 
HPKE to generate a shared secret used to encrypt the CEK. This layer conveys the 
encrypted CEK in the encCEK structure. The protected header MUST contain the HPKE 
alg parameter and the unprotected header MUST contain the 'encapsulated_key' parameter.
The unprotected header MAY contain the kid parameter to identify the static recipient
public key the sender has been using with HPKE.

This two-layer structure is used to encrypt content that can also be shared with
multiple parties at the expense of a single additional encryption operation.
As stated above, the specification uses a CEK to encrypt the content at layer 0.

The COSE_recipient structure, shown in {{cddl-hpke}}, is repeated for each
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

## Info Parameter {#info}

The HPKE specification defines the "info" parameter as a context information
structure that is used to ensure that the derived keying material is bound to
the context of the transaction. 

This section provides a suggestion for constructing the info structure. HPKE leaves
the info parameter for these two functions as optional. Application profiles of this
specification MAY populate the fields of the COSE_KDF_Context structure or MAY use
a different structure as input to the "info" parameter. If no content for the
"info" parameter is not supplied, it defaults to a zero-length byte string.

This specification re-uses the context information structure defined in
{{RFC9053}} as a foundation for the info structure. This payload becomes the content
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
{: #cddl-cose-kdf title="COSE_KDF_Context Data Structure as 'info' Parameter for HPKE"}

# Ciphersuite Registration

This specification registers a number of ciphersuites for use with HPKE.
A ciphersuite is thereby a combination of several algorithm configurations:

- HPKE Mode
- KEM algorithm
- KDF algorithm
- AEAD algorithm

The "KEM", "KDF", and "AEAD" values are conceptually taken from the HPKE IANA
registry {{HPKE-IANA}}. Hence, COSE-HPKE cannot use a algorithm combination
that is not already available with HPKE.

For better readability of the algorithm combination ciphersuites labels are
build according to the following scheme: 

~~~
HPKE-<Version>-<Mode>-<KEM>-<KDF>-<AEAD>
~~~

The "Mode" indicator may be populated with the following values from
Table 1 of {{RFC9180}}:

- "Base" refers to "mode_base" described in Section 5.1.1 of {{RFC9180}},
which only enables encryption to the holder of a given KEM private key.
- "PSK" refers to "mode_psk", described in Section 5.1.2 of {{RFC9180}},
which authenticates using a pre-shared key.
- "Auth" refers to "mode_auth", described in Section 5.1.3 of {{RFC9180}},
which authenticates using an asymmetric key.
- "Auth_Psk" refers to "mode_auth_psk", described in Section 5.1.4 of {{RFC9180}},
which authenticates using both a PSK and an asymmetric key.

For a list of ciphersuite registrations, please see {{IANA}}. The following
table summarizes the relationship between the ciphersuites registered in this
document and maps them to the values from the HPKE IANA registry.

~~~
+-----------------------------------------------------+------------------+
| COSE-HPKE                                           |      HPKE        |
| Ciphersuite                                         | KEM | KDF | AEAD |
+-----------------------------------------------------+-----+-----+------+
| HPKE-v1-Base-P256-SHA256-AES128GCM                  |0x10 | 0x1 | 0x1  |
| HPKE-v1-Base-P256-SHA256-ChaCha20Poly1305           |0x10 | 0x1 | 0x3  |
| HPKE-v1-Base-P384-SHA384-AES256GCM                  |0x11 | 0x2 | 0x2  |
| HPKE-v1-Base-P384-SHA384-ChaCha20Poly1305           |0x11 | 0x2 | 0x3  |
| HPKE-v1-Base-P521-SHA512-AES256GCM                  |0x12 | 0x3 | 0x2  |
| HPKE-v1-Base-P521-SHA512-ChaCha20Poly1305           |0x12 | 0x3 | 0x3  |
| HPKE-v1-Base-X25519-SHA256-AES128GCM                |0x20 | 0x1 | 0x1  |
| HPKE-v1-Base-X25519-SHA256-ChaCha20Poly1305         |0x20 | 0x1 | 0x3  |
| HPKE-v1-Base-X448-SHA512-AES256GCM                  |0x21 | 0x3 | 0x2  |
| HPKE-v1-Base-X448-SHA512-ChaCha20Poly1305           |0x21 | 0x3 | 0x3  |
| HPKE-v1-Base-X25519Kyber768-SHA256-AES256GCM        |0x30 | 0x1 | 0x2  |
| HPKE-v1-Base-X25519Kyber768-SHA256-ChaCha20Poly1305 |0x30 | 0x1 | 0x3  |
+-----------------------------------------------------+-----+-----+------+
~~~

As the list indicates, the ciphersuite labels have been abbreviated at least
to some extend to maintain the tradeoff between readability and length.

# Examples

## Single Recipient / One Layer Example {#one-layer-example}

This example assumes that a sender wants to communicate an
encrypted payload to a single recipient in the most efficient way.

An example of the COSE_Encrypt0 structure using the HPKE scheme is
shown in {{hpke-example-one}}. Line breaks and comments have been inserted
for better readability. 

This example uses HPKE-v1-Base-P256-SHA256-AES128GCM as the algorithm,
which correspond to the following HPKE algorithm combination:

- KEM: DHKEM(P-256, HKDF-SHA256)
- KDF: HKDF-SHA256
- AEAD: AES-128-GCM
- Mode: Base
- payload: "This is the content"
- aad: ""

~~~
16([
    / alg = HPKE-v1-Base-P256-SHA256-AES128GCM /
    h'a1011823',
    {
        / kid /
        4: h'3031',
        / encapsulated_key /
        -4: h'048c6f75e463a773082f3cb0d3a701348a578c67
              80aba658646682a9af7291dfc277ec93c3d58707
              818286c1097825457338dc3dcaff367e2951342e
              9db30dc0e7',
    },
    / encrypted plaintext /
    h'ee22206308e478c279b94bb071f3a5fbbac412a6effe34195f7
      c4169d7d8e81666d8be13',
])
~~~
{: #hpke-example-one title="COSE_Encrypt0 Example for HPKE"}

## Multiple Recipients / Two Layer {#two-layer-example}

In this example we assume that a sender wants to transmit a
payload to two recipients using the two-layer structure.
Note that it is possible to send two single-layer payloads, 
although it will be less efficient.

An example of the COSE_Encrypt structure using the HPKE scheme is
shown in {{hpke-example-two}}. Line breaks and comments have been
inserted for better readability. 

This example uses AES-128-GCM for encryption of the plaintext
"This is the content." with aad="" at layer 0. The ciphertext is
detached.

At the recipient structure at layer 1, this example uses
HPKE-v1-Base-P256-SHA256-AES128GCM as the algorithm, which
correspond to the following HPKE algorithm combination:

- KEM: DHKEM(P-256, HKDF-SHA256)
- KDF: HKDF-SHA256
- AEAD: AES-128-GCM
- Mode: Base

~~~
96_0([
    / alg = AES-128-GCM (1) /
    h'a10101',
    {
      / iv /
      5: h'67303696a1cc2b6a64867096'
    },
    / detached ciphertext /
    h'',
    [
        [
            / alg = HPKE-v1-Base-P256-SHA256-AES128GCM /
            h'a1011823',
            {
                / kid /
                4: h'3031',
                / encapsulated_key /
                36: h'0421ccd1b00dd958d77e10399c
                      97530fcbb91a1dc71cb3bf41d9
                      9fd39f22918505c973816ecbca
                      6de507c4073d05cceff73e0d35
                      f60e2373e09a9433be9e95e53c',
            },
            / ciphertext containing encrypted CEK /
            h'bb2f1433546c55fb38d6f23f5cd95e1d72eb4
              c129b99a165cd5a28bd75859c10939b7e4d',
        ],
        [
            / alg = HPKE-v1-Base-P256-SHA256-AES128GCM /
            h'a1011823',
            {
                / kid /
                4: h'313233', // kid
                / encapsulated_key /
                -4: h'6de507c4073d05cceff73e0d35
                      f60e2373e09a9433be9e95e53c
                      9fd39f22918505c973816ecbca
                      6de507c4073d05cceff73e0d35
                      f60e2373e09a9433be9e95e53c',
            },
            / ciphertext containing encrypted CEK /
            h'c4169d7d8e81666d8be13bb2f1433546c55fb
              c129b99a165cd5a28bd75859c10939b7e4d',
        ]        
    ],
])
~~~
{: #hpke-example-two title="COSE_Encrypt Example for HPKE"}

To offer authentication of the sender the payload in {{hpke-example-two}}
is signed with a COSE_Sign1 wrapper, which is outlined in {{hpke-example-sign}}.
The payload in {{hpke-example-sign}} is meant to contain the content of
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

This specification is based on HPKE and the security considerations of
{{RFC9180}} are therefore applicable also to this specification.

HPKE assumes the sender is in possession of the public key of the recipient and
HPKE COSE makes the same assumptions. Hence, some form of public key distribution
mechanism is assumed to exist but outside the scope of this document.

HPKE relies on a source of randomness to be available on the device. Additionally, 
with the two layer structure the CEK is randomly generated and it MUST be
ensured that the guidelines in {{RFC8937}} for random number generations are followed. 

HPKE in Base mode does not offer authentication as part of the HPKE KEM. In this
case COSE constructs like COSE_Sign, COSE_Sign1, COSE_MAC, or COSE_MAC0 can be
used to add authentication. HPKE also offers modes that offer authentication.

If COSE_Encrypt or COSE_Encrypt0 is used with a detached ciphertext then the
subsequently applied integrity protection via COSE_Sign, COSE_Sign1, COSE_MAC, 
or COSE_MAC0 does not cover this detached ciphertext. Implementers MUST ensure
that the detached ciphertext also experiences integrity protection. This is, for
example, the case when an AEAD cipher is used to produce the detached ciphertext
but may not be guaranteed by non-AEAD ciphers.

#  IANA Considerations {#IANA}

This document requests IANA to add new values to the 'COSE Algorithms' and to 
the 'COSE Header Parameters' registries in the 'Standards Action 
With Expert Review category.

## COSE Algorithms Registry

-  Name: HPKE-v1-Base-P256-SHA256-AES128GCM
-  Value: TBD1 (Assumed: 35)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the AES-128-GCM AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-v1-Base-P256-SHA256-ChaCha20Poly1305
-  Value: TBD2 (Assumed: 36)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the ChaCha20Poly1305 AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-v1-Base-P384-SHA384-AES256GCM
-  Value: TBD3 (Assumed: 37)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the AES-256-GCM AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-v1-Base-P384-SHA384-ChaCha20Poly1305
-  Value: TBD4 (Assumed: 38)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the ChaCha20Poly1305 AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-v1-Base-P521-SHA512-AES256GCM
-  Value: TBD5 (Assumed: 39)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-v1-Base-P521-SHA512-ChaCha20Poly1305
-  Value: TBD6 (Assumed: 40)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the ChaCha20Poly1305 AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-v1-Base-X25519-SHA256-AES128GCM
-  Value: TBD7 (Assumed: 41)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the AES-128-GCM AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-v1-Base-X25519-SHA256-ChaCha20Poly1305
-  Value: TBD8 (Assumed: 42)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-v1-Base-X448-SHA512-AES256GCM
-  Value: TBD9 (Assumed: 43)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-v1-Base-X448-SHA512-ChaCha20Poly1305
-  Value: TBD10 (Assumed: 44)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the ChaCha20Poly1305 AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-v1-Base-X25519Kyber768-SHA256-AES256GCM
-  Value: TBD11 (Assumed: 250)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the X25519Kyber768Draft00 KEM, the HKDF-SHA256 KDF, and the AES-256-GCM AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: No

-  Name: HPKE-v1-Base-X25519Kyber768-SHA256-ChaCha20Poly1305
-  Value: TBD12 (Assumed: 251)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the X25519Kyber768Draft00 KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: No

## COSE Header Parameters

-  Name: encapsulated_key
-  Label: TBDX (Assumed: -4)
-  Value type: bstr
-  Value Registry: N/A
-  Description: HPKE encapsulated key
-  Reference: [[This specification]]
 
--- back

# Contributors

We would like thank the following individuals for their contributions
to the design of embedding the HPKE output into the COSE structure 
following a long and lively mailing list discussion. 

- Richard Barnes
- Ilari Liusvaara

Finally, we would like to thank Russ Housley and Brendan Moran for their
contributions to the draft as co-authors of initial versions.

# Acknowledgements

We would like to thank John Mattsson, Mike Prorock, Michael Richardson,
and Goeran Selander for their review feedback.

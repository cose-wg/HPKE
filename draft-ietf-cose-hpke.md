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
  
--- abstract

This specification defines hybrid public-key encryption (HPKE) for use with 
CBOR Object Signing and Encryption (COSE). HPKE offers a variant of
public-key encryption of arbitrary-sized plaintexts for a recipient public key.

HPKE works for any combination of an asymmetric key encapsulation mechanism (KEM),
key derivation function (KDF), and authenticated encryption with
additional data (AEAD) function. Authentication for HPKE in COSE is
provided by COSE-native security mechanisms.

This document defines the use of the HPKE with COSE.

--- middle

#  Introduction

Hybrid public-key encryption (HPKE) {{RFC9180}} is a scheme that 
provides public key encryption of arbitrary-sized plaintexts given a 
recipient's public key. HPKE utilizes a non-interactive ephemeral-static 
Diffie-Hellman exchange to establish a shared secret. The motivation for
standardizing a public key encryption scheme is explained in the introduction
of {{RFC9180}}.

The HPKE specification defines several features for use with public key encryption
and a subset of those features is applied to COSE ({{RFC9052}}, {{RFC9053}}). Since COSE provides
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

When the alg value is set to any of algorithms registered by this
specification then the 'encapsulated_key' header parameter MUST
be present in the unprotected header parameter.

The 'encapsulated_key' parameter contains the encapsulated key, which is
output of the HPKE KEM, and is a bstr.

### Single Recipient / One Layer Structure {#one-layer}

With the one layer structure the information carried inside the 
COSE_recipient structure is embedded inside the COSE_Encrypt0. 

HPKE is used to directly encrypt the plaintext. The resulting ciphertext
MAY be included in the COSE_Encrypt0 or MAY be detached. If a payload is
transported separately then it is called "detached content". A nil CBOR
object is placed in the location of the ciphertext. See Section 5
of {{RFC9052}} for a description of detached payloads.

The sender MUST set the alg parameter in the protected header, which
indicates the use of HPKE. 

The sender MUST place the 'encapsulated_key' parameter into the unprotected
header. Although the use of the kid parameter in COSE_Encrypt0 is
discouraged by RFC 9052, this specification allows profiles of this
specification to use the kid parameter (or other parameters) to
identify the static recipient public key used by the sender. If the
COSE_Encrypt0 contains the kid then the recipient may use it to
select the appropriate private key.

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
        36: h'048c6f75e463a773082f3cb0d3a701348a578c67
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
                36: h'6de507c4073d05cceff73e0d35
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

This specification is based on HPKE and the security considerations of HPKE
{{RFC9180}} are therefore applicable also to this specification.

HPKE assumes the sender is in possession of the public key of the recipient and
HPKE COSE makes the same assumptions. Hence, some form of public key distribution
mechanism is assumed to exist.

HPKE relies on a source of randomness to be available on the device. Additionally, 
with the two layer structure the CEK is randomly generated and the it MUST be
ensured that the guidelines in {{RFC8937}} for random number generations are followed. 

HPKE in Base mode does not offer authentication as part of the HPKE KEM. In this
case COSE constructs like COSE_Sign, COSE_Sign1, COSE_MAC, or COSE_MAC0 can be
used. HPKE also offers modes that offer authentication.

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

-  Name: HPKE-v1-Base-X25519_SHA256_ChaCha20Poly1305
-  Value: TBD2 (Assumed: 36)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-v1-Base-P384-SHA384_AES256GCM
-  Value: TBD3 (Assumed: 37)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the AES-256-GCM AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-v1-Base-P521_SHA512_AES256GCM
-  Value: TBD4 (Assumed: 38)
-  Description: Cipher suite for COSE-HPKE version 1 in Base Mode that uses the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

## COSE Header Parameters

-  Name: encapsulated_key
-  Label: TBDX (Assumed: 36)
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

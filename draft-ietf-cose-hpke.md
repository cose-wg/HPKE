---
title: Use of Hybrid Public-Key Encryption (HPKE) with CBOR Object Signing and Encryption (COSE)
abbrev: COSE HPKE
docname: draft-ietf-cose-hpke-10
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
  email: hannes.tschofenig@gmx.net
  abbrev: H-BRS
  organization: University of Applied Sciences Bonn-Rhein-Sieg
  country: Germany
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
  organization: bibital
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
  STD94:
  
informative:
  RFC8937:
  RFC2630:
  I-D.irtf-cfrg-dnhpke:
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
recipient's public key.

This document defines the use of the HPKE with COSE ({{RFC9052}}, {{RFC9053}}).

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

This specification supports two modes of HPKE in COSE, namely 

  *  HPKE Direct Encryption mode, where HPKE is used to encrypt the plaintext. This mode can only be used with a single recipient. {{one-layer}} provides the details.
  
  *  HPKE Key Encryption mode, where HPKE is used to encrypt a content encryption key (CEK) and the CEK is subsequently used to encrypt the plaintext. This mode supports multiple recipients. {{two-layer}} 
  provides the details.

In both cases a new COSE header parameter, called 'ek',
is used to convey the content of the enc structure defined in the HPKE
specification. "Enc" represents the serialized public key.

For use with HPKE the 'ek' header parameter MUST
be present in the unprotected header parameter and MUST contain
the encapsulated key, which is output of the HPKE KEM, and it
is a bstr.

### HPKE Direct Encryption Mode {#one-layer}

This mode applies if the COSE_Encrypt0 structure uses a COSE-HPKE algorithm and has no recipients.

Because COSE-HPKE supports header protection, if the 'alg' parameter is present, it MUST be included
in the protected header and MUST be a COSE-HPKE algorithm.

Although the use of the 'kid' parameter in COSE_Encrypt0 is
discouraged by RFC 9052, this documents RECOMMENDS the use of the 'kid' parameter
(or other parameters) to explicitly identify the static recipient public key
used by the sender. If the COSE_Encrypt0 contains the 'kid' then the recipient may
use it to select the appropriate private key.

When encrypting, the inputs to the HPKE Seal operation are set as follows:

- kem_id: Depends on the COSE-HPKE algorithm used.
- pkR: The recipient public key, converted into an HPKE public key.
- kdf_id: Depends on the COSE-HPKE algorithm used.
- aead_id: Depends on the COSE-HPKE algorithm used.
- info: empty string.
- aad: Canonical encoding of the Enc_structure from {{RFC9052}}).
- pt: The raw message plaintext.

The outputs are used as follows:

- enc: MUST be placed raw into the 'ek' (encapsulated key) parameter in the unprotected bucket.
- ct: MUST be used as layer ciphertext. If not using detached content, this is directly placed as
ciphertext in COSE_Encrypt0 structure. Otherwise, it is transported separately and the ciphertext field is nil.
See Section 5 of {{RFC9052}} for a description of detached payloads.

When decrypting, the inputs to the HPKE Open operation are set as follows:

- kem_id: Depends on the COSE-HPKE algorithm used.
- skR: The recipient private key, converted into an HPKE private key.
- kdf_id: Depends on the COSE-HPKE algorithm used.
- aead_id: Depends on the COSE-HPKE algorithm used.
- info: empty string.
- aad: Canonical encoding of the Enc_structure from {{RFC9052}}).
- enc: The contents of the layer 'ek' parameter.
- ct: The contents of the layer ciphertext.

The plaintext output is the raw message plaintext. 

The COSE_Encrypt0 MAY be tagged or untagged.

An example is shown in {{one-layer-example}}.

### HPKE Key Encryption Mode {#two-layer}

This mode is selected if COSE_recipient structure uses a COSE-HPKE algorithm.


In this approach the following layers are involved: 

- Layer 0 (corresponding to the COSE_Encrypt structure) contains the content (plaintext)
encrypted with the CEK. This ciphertext may be detached, and if not detached, then
it is included in the COSE_Encrypt structure.

- Layer 1 (corresponding to a recipient structure) contains parameters needed for 
HPKE to generate a shared secret used to encrypt the CEK. This layer conveys the 
encrypted CEK in the COSE_recipient structure using a COSE-HPKE algorithm.
The unprotected header MAY contain the kid parameter to identify the static recipient
public key the sender has been using with HPKE.

This two-layer structure is used to encrypt content that can also be shared with
multiple parties at the expense of a single additional encryption operation.
As stated above, the specification uses a CEK to encrypt the content at layer 0.

#### Recipient Encryption

This describes the Recipient_structure.
It serves instead of COSE_KDF_Context for COSE-HPKE recipients (and possibly other COSE algorithms defined outside this document).
It MUST be used for COSE-HPKE recipients as it provides the protection for recipient protected headers.
It is patterned after the Enc_structure in {{RFC9052}}, but is specifically for a COSE_recipient, never a COSE_Encrypt.
The COSE_KDF_Context MUST NOT be used in COSE-HPKE.

~~~
Recipient_structure = [ 
    context: "Recipient",
    next_layer_alg: int/tstr,
    recipient_protected_header: empty_or_serialize_map,
    recipient_aad: bstr
]
~~~

- "next_layer_alg" is the algorithm ID of the COSE layer for which the COSE_recipient is encrypting a key.
It is the algorithm that the key MUST be used with.
This value MUST match the alg parameter in the next lower COSE layer.
(This serves the same purpose as the alg ID in the COSE_KDF_Context.
It also mitigates attacks where a person-in-the-middle changes the following layer algorithm from an AEAD algorithm to one that is not foiling the protection of the following layer headers).

- "recipient_protected_header" contains the protected headers from the COSE_recipient CBOR-encoded deterministically with the "Core Deterministic Encoding Requirements", specified in Section 4.2.1 of RFC 8949 {{STD94}}.

- "recipient_aad" contains any additional context the application wishes to protect.
If none, it is a zero-length string.
This is distinct from the external_aad for the whole COSE encrypt.
It is per-recipient.
Since it is not a header, it may be secret data that is not transmitted.
It provides a means to convey many of the fields in COSE_KDF_Context.


#### COSE-HPKE Recipient Construction

Because COSE-HPKE supports header protection by definition, if 'alg' parameter is present, it MUST be in protected bucket, and SHALL be a COSE-HPKE algorithm.

The unprotected header MAY contain the kid parameter to identify the static recipient public key the sender used.

When encrypting, the inputs to the HPKE Seal operation are set as follows:

- kem_id: Depends on the COSE-HPKE algorithm used.
- pkR: The recipient public key, converted into HPKE public key.
- kdf_id: Depends on the COSE-HPKE algorithm used.
- aead_id: Depends on the COSE-HPKE algorithm used.
- info: empty string.
- aad: Canonical encoding of the Recipient_structure.
- pt: The raw key for the next layer down.

The outputs are used as follows:

- enc: MUST be placed raw into the 'ek' (encapsulated key) parameter in the unprotected bucket.
- ct: MUST be placed raw in the ciphertext field in the COSE_recipient.

When decrypting, the inputs to the HPKE Open operation are set as follows:

- kem_id: Depends on the COSE-HPKE algorithm used.
- skR: The recipient private key, converted into HPKE private key.
- kdf_id: Depends on the COSE-HPKE algorithm used.
- aead_id: Depends on the COSE-HPKE algorithm used.
- info: empty string.
- aad: Canonical encoding of the Recipient_structure.
- enc: The contents of the layer 'ek' parameter.
- ct: The contents of the layer ciphertext field.

The plaintext output is the raw key for the next layer down.

It is not necessary to fill in recipient_aad as HPKE itself covers the attacks that recipient_aad (and COSE_KDF_Context (and SP800-56A)) are used to mitigate.
COSE-HPKE use cases may use it for any purpose they wish, but it should generally be for small identifiers, context or secrets, not to protect bulk external data.
Bulk external data should be protected at layer 0 with external_aad.


The COSE_recipient structure is repeated for each recipient.

When encrypting the content at layer 0 then the instructions in
Section 5.3 of {{RFC9052}} MUST to be followed, which includes the
calculation of the authenticated data strcture.

An example is shown in {{two-layer-example}}.

## Key Representation {#key-representation}

The COSE_Key with the existing key types can be used to represent KEM private
or public keys. When using a COSE_Key for COSE-HPKE, the following checks are made:

* If the "kty" field is "AKP", then the public and private keys SHALL be raw HPKE public and private
keys (respectively) for the KEM used by the algorithm.
* Otherwise, the key MUST be suitable for the KEM used by the algorithm. In case the "kty" parameter
is "EC2" or "OKP", this means the value of "crv" parameter is suitable. For the algorithms defined in
this document, the valid combinations of the KEM, "kty" and "crv" are shown in  {{ciphersuite-kty-crv}}.
* If the "key_ops" field is present, it MUST include only "derive bits" for the private key
  and MUST be empty for the public key.

Examples of the COSE_Key for COSE-HPKE are shown in {{key-representation-example}}.


# Ciphersuite Registration

A ciphersuite is a group of algorithms, often sharing component algorithms
such as hash functions, targeting a security level.
A COSE-HPKE algorithm is composed of the following choices:

- HPKE Mode
- KEM Algorithm
- KDF Algorithm
- AEAD Algorithm

The "KEM", "KDF", and "AEAD" values are chosen from the HPKE IANA
registry {{HPKE-IANA}}. 

For readability the algorithm ciphersuites labels are built according
to the following scheme: 

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
document, which all use the "Base" mode and the values registered in the
HPKE IANA registry {{HPKE-IANA}}.

~~~
+--------------------------------------------------+------------------+
| COSE-HPKE                                        |      HPKE        |
| Cipher Suite Label                               | KEM | KDF | AEAD |
+--------------------------------------------------+-----+-----+------+
| HPKE-0                                           |0x10 | 0x1 | 0x1  |
| HPKE-1                                           |0x11 | 0x2 | 0x2  |
| HPKE-2                                           |0x12 | 0x3 | 0x2  |
| HPKE-3                                           |0x20 | 0x1 | 0x1  |
| HPKE-4                                           |0x20 | 0x1 | 0x3  |
| HPKE-5                                           |0x21 | 0x3 | 0x2  |
| HPKE-6                                           |0x21 | 0x3 | 0x3  |
+--------------------------------------------------+-----+-----+------+
~~~

As the list indicates, the ciphersuite labels have been abbreviated at least
to some extend to maintain the tradeoff between readability and length.

The ciphersuite list above is a minimal starting point. Additional
ciphersuites can be registered into the already existing registry.
For example, once post-quantum cryptographic algorithms have been standardized
it might be beneficial to register ciphersuites for use with COSE-HPKE.
Additionally, ciphersuites utilizing the compact encoding of the public keys,
as defined in {{I-D.irtf-cfrg-dnhpke}}, may be standardized for use in
constrained environments.

As a guideline for ciphersuite submissions to the IANA CoSE algorithm
registry, the designated experts must only register combinations of 
(KEM, KDF, AEAD) triple that consitute valid combinations for use with
HPKE, the KDF used should (if possible) match one internally used by the
KEM, and components should not be mixed between global and national standards.

## COSE_Keys for COSE-HPKE Ciphersuites

The COSE-HPKE algorithm uniquely determines the KEM for which a COSE_Key is used.
The following mapping table shows the valid combinations
of the KEM used, COSE_Key type and its curve/key subtype.

~~~
+---------------------+--------------+
| HPKE KEM id         | COSE_Key     |
|                     | kty | crv    |
+---------------------+-----+--------+
| 0x0010, 0x0013      | EC2 | P-256  |
| 0x0011, 0x0014      | EC2 | P-384  |
| 0x0012, 0x0015      | EC2 | P-521  |
| 0x0020              | OKP | X25519 |
| 0x0021              | OKP | X448   |
+---------------------+-----+--------+
~~~
{: #ciphersuite-kty-crv title="COSE_Key Types and Curves for COSE-HPKE Ciphersuites"}

# Examples

This section provides a set of examples that shows all COSE message types
(COSE_Encrypt0, COSE_Encrypt and COSE_MAC) to which the COSE-HPKE can be
applied, and also provides some examples of key representation for HPKE KEM.

Each example of the COSE message includes the following information
that can be used to check the interoperability of COSE-HPKE implementations:

- plaintext: Original data of the encrypted payload.
- external_aad: Externally supplied AAD.
- skR: A recipient private key.
- skE: An ephemeral sender private key paired with the encapsulated key.

## HPKE Direct Encryption Mode {#one-layer-example}

This example assumes that a sender wants to communicate an
encrypted payload to a single recipient in the most efficient way.

An example of the HPKE Direct Encryption Mode is
shown in {{hpke-example-one}}. Line breaks and comments have been inserted
for better readability.

This example uses the following:

- alg: HPKE-0
- plaintext: "This is the content."
- external_aad: "COSE-HPKE app"
- skR: h'57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3'
- skE: h'42dd125eefc409c3b57366e721a40043fb5a58e346d51c133128a77237160218'

~~~
16([
    / alg = HPKE-0 (Assumed: 35) /
    h'a1011823',
    {
        / kid /
        4: h'3031',
        / ek /
        -4: h'045df24272faf43849530db6be01f42708b3c3a9
              df8e268513f0a996ed09ba7840894a3fb946cb28
              23f609c59463093d8815a7400233b75ca8ecb177
              54d241973e',
    },
    / encrypted plaintext /
    h'35aa3d98739289b83751125abe44e3b977e4b9abbf2c8cfaade
      b15f7681eef76df88f096',
])
~~~
{: #hpke-example-one title="COSE_Encrypt0 Example for HPKE"}

## HPKE Key Encryption Mode {#two-layer-example}

In this example we assume that a sender wants to transmit a
payload to two recipients using the HPKE Key Encryption mode.
Note that it is possible to send two single-layer payloads, 
although it will be less efficient.

### COSE_Encrypt

An example of the COSE_Encrypt structure using the HPKE scheme is
shown in {{hpke-example-cose-encrypt}}. Line breaks and comments have been
inserted for better readability. 

This example uses the following:

TODO: recompute this for Recipient_structure

- Encryption alg: AES-128-GCM
- plaintext: "This is the content."
- detatched ciphertext: h'cc168c4e148c52a83010a75250935a47ccb8682deebcef8fce5d60c161e849f53a2dc664'
- kid:"01"
    - alg: HPKE-0
    - external_aad: "COSE-HPKE app"
    - skR: h'57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3'
    - skE: h'97ad883f949f4cdcb1301b9446950efd4eb519e16c4a3d78304eec832692f9f6'
- kid:"02"
    - alg: HPKE-4
    - external_aad: "COSE-HPKE app"
    - skR: h'bec275a17e4d362d0819dc0695d89a73be6bf94b66ab726ae0b1afe3c43f41ce'
    - skE: h'b8ed3f4df56c230e36fa6620a47f24d08856d242ea547c5521ff7bd69af8fd6f'

~~~
96_0([
    / alg = AES-128-GCM (1) /
    h'a10101',
    {
        / iv /
        5: h'b3fb95dde18c6f90a9f0ae55',
    },
    / detached ciphertext /
    null,
    [
        [
            / alg = HPKE-0 (Assumed: 35) /
            h'a1011823',
            {
                / kid /
                4: h'3031',
                / ek /
                -4: h'04d97b79486fe2e7b98fb1bd43
                      c4faee316ff38d28609a1cf568
                      40a809298a91e601f1cc0c2ba4
                      6cb67b41f4651b769cafd9df78
                      e58aa7f5771291bd4f0f420ba6',
            },
            / ciphertext containing encrypted CEK /
            h'24450f54ae93375351467d17aa7a795cfede2
              c03eced1ad21fcb7e7c2fe64397',
        ],
        [
            / alg = HPKE-4 (Assumed: 42) /
            h'a101182a',
            {
                / kid /
                4: h'3032',
                / ek /
                -4: h'd1afbdc95b0e735676f6bca34f
                      be50f2822259ac09bfc3c500f1
                      4a05de9b2833',
            },
            / ciphertext containing encrypted CEK /
            h'079b443ec6dfcda6a5f8748aff3875146a8ed
              40359e1279b545166385d8d9b59',
        ],
    ],
])
~~~
{: #hpke-example-cose-encrypt title="COSE_Encrypt Example for HPKE"}

To offer authentication of the sender the payload in {{hpke-example-cose-encrypt}}
is signed with a COSE_Sign1 wrapper, which is outlined in {{hpke-example-sign}}.
The payload in {{hpke-example-sign}} is meant to contain the content of
{{hpke-example-cose-encrypt}}.

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

### COSE_MAC

An example of the COSE_MAC structure using the HPKE scheme is
shown in {{hpke-example-cose-mac}}.

This example uses the following:

- MAC alg: HMAC 256/256
- payload: "This is the content."
- kid:"01"
    - alg: HPKE-0
    - external_aad: "COSE-HPKE app"
    - skR: h'57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3'
    - skE: h'e5dd9472b5807636c95be0ba2575020ba91cbb3561b52be141da89678c664307'
- kid:"02"
    - alg: HPKE-4
    - external_aad: "COSE-HPKE app"
    - skR: h'bec275a17e4d362d0819dc0695d89a73be6bf94b66ab726ae0b1afe3c43f41ce'
    - skE: h'78a49d7af71b5244498e943f361aa0250184afc48b8098a68ae97ccd2cd7e56f'

~~~
97_0([
    / alg = HMAC 256/256 (5) /
    h'a10105',
    {},
    / payload = 'This is the content.' /
    h'546869732069732074686520636f6e74656e742e',
    / tag /
    h'5cdcf6055fcbdb53b4001d8fb88b2a46b200ed28e1e
	  d77e16ddf43fb3cac3a98',
    [
        [
            / alg = HPKE-0 (Assumed: 35) /
            h'a1011823',
            {
                / kid = '01' /
                4: h'3031',
                / ek /
                -4: h'043ac21632e45e1fbd733f002a
                      621aa4f3d94737adc395d5a7cb
                      6e9554bd1ad273aec991493786
                      d72616d9759bf8526e6e20c1ed
                      c41ba5739f2b2e441781aa0eb4',
            },
            / ciphertext containing encrypted MAC key /
            h'5cee2b4235a7ff695164f7a8d1e79ccf3ca3d
              e8b22f3592626020a95b2a8d3fb4d7aa7fe37
              432426ee70073a368f29d1',
        ],
        [
            / alg = HPKE-4 (Assumed: 42) /
            h'a101182a',
            {
                / kid = '02' /
                4: h'3032',
                / ek /
                -4: h'02cffacc60def3bb3d0a1c3661
                      227c9de8dc2b1d3939dd2c07d4
                      49ebb0bba324',
            },
            / ciphertext containing encrypted MAC key /
            h'3f5b8b60271d5234dbea554dc1461d0239e9f
              4589f6415e8563b061dbcb37795a616111b78
              2b4c589b534309327ffadc',
        ],
    ],
])
~~~
{: #hpke-example-cose-mac title="COSE_MAC Example for HPKE"}


## Key Representation {#key-representation-example}

Examples of private and public KEM key representation are shown below.

### KEM Public Key for HPKE-0

~~~
{
    / kty = 'EC2' /
    1: 2,
    / kid = '01' /
    2: h'3031',
    / alg = HPKE-0 (Assumed: 35) /
    3: 35,
    / crv = 'P-256' /
    -1: 1,
    / x /
    -2: h'65eda5a12577c2bae829437fe338701a10aaa375
	      e1bb5b5de108de439c08551d',
    / y /
    -3: h'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af
	      7e0ca7ca7e9eecd0084d19c'
}
~~~
{: #hpke-example-key-1 title="Key Representation Example for HPKE-0"}


### KEM Private Key for HPKE-0

~~~
{
    / kty = 'EC2' /
    1: 2,
    / kid = '01' /
    2: h'3031',
    / alg = HPKE-0 (Assumed: 35) /
    3: 35,
    / key_ops = ['derive_bits'] /
    4: [8],
    / crv = 'P-256' /
    -1: 1,
    / x /
    -2: h'bac5b11cad8f99f9c72b05cf4b9e26d244dc189f7
	      45228255a219a86d6a09eff',
    / y /
    -3: h'20138bf82dc1b6d562be0fa54ab7804a3a64b6d72
	      ccfed6b6fb6ed28bbfc117e',
    / d /
    -4: h'57c92077664146e876760c9520d054aa93c3afb04
	      e306705db6090308507b4d3',
}
~~~
{: #hpke-example-key-2 title="Key Representation Example for HPKE-0"}


### KEM Public Key for HPKE-4

~~~
{
    / kty = 'OKP' /
    1: 1,
    / kid = '11' /
    2: h'3131',
    / alg = HPKE-4 (Assumed: 42) /
    3: 42,
    / crv = 'X25519' /
    -1: 4,
    / x /
    -2: h'cb7c09ab7b973c77a808ee05b9bbd373b55c06eaa
	      9bd4ad2bd4e9931b1c34c22',
}
~~~
{: #hpke-example-key-3 title="Key Representation Example for HPKE-4"}

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
the 'COSE Header Parameters' registries.

## COSE Algorithms Registry

-  Name: HPKE-0
-  Value: TBD1 (Assumed: 35)
-  Description: Cipher suite for COSE-HPKE in Base Mode that uses the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the AES-128-GCM AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-1
-  Value: TBD3 (Assumed: 37)
-  Description: Cipher suite for COSE-HPKE in Base Mode that uses the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the AES-256-GCM AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-2
-  Value: TBD5 (Assumed: 39)
-  Description: Cipher suite for COSE-HPKE in Base Mode that uses the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-3
-  Value: TBD7 (Assumed: 41)
-  Description: Cipher suite for COSE-HPKE in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the AES-128-GCM AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-4
-  Value: TBD8 (Assumed: 42)
-  Description: Cipher suite for COSE-HPKE in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-5
-  Value: TBD9 (Assumed: 43)
-  Description: Cipher suite for COSE-HPKE in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

-  Name: HPKE-6
-  Value: TBD10 (Assumed: 44)
-  Description: Cipher suite for COSE-HPKE in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the ChaCha20Poly1305 AEAD.
-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

## COSE Header Parameters

-  Name: ek
-  Label: TBDX (Assumed: -4)
-  Value type: bstr
-  Value Registry: N/A
-  Description: HPKE encapsulated key
-  Reference: [[This specification]]
 
--- back

# Contributors

We would like thank the following individuals for their contributions
to the design of embedding the HPKE output into the COSE structure 
following a long and lively mailing list discussion:

- Richard Barnes
- Ilari Liusvaara

Finally, we would like to thank Russ Housley and Brendan Moran for their
contributions to the draft as co-authors of initial versions.

# Acknowledgements

We would like to thank John Mattsson, Mike Prorock, Michael Richardson,
and Goeran Selander for their review feedback.

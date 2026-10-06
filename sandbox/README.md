# The reference server in the Sweden Connect Sandbox

The `sandbox` profile runs the Sweden Connect reference authentication server as both SAML Identity Provider and
OpenID Provider in the Sweden Connect Sandbox federation, at `https://ref.sandbox.swedenconnect.se`. This directory
is local and is never committed.

## Starting the service

Build the project with `mvn clean install`, then from the root of the repository:

```bash
REF_DATA_DIR=/tmp/reference java -jar sweden-connect-reference/target/sweden-connect-reference-authn-server-<version>.jar \
  --spring.profiles.active=sandbox \
  --spring.config.additional-location=file:./sandbox/
```

The service listens on 8443 (HTTPS) and the Actuator on 8444. Reached as `localhost`, the base URL does not match, so
use a hosts entry or `curl --resolve ref.sandbox.swedenconnect.se:8443:127.0.0.1`.

Until the service is registered in the federation, fetching its own trust marks fails and is logged. The service still
starts. It also starts when the metadata service or the federation cannot be reached.

## Environment variables

| Variable | What it is | Default |
| :--- | :--- | :--- |
| `REF_CONFIG_LOCATION` | Where the files that are read live. Every file below is relative to it. | `file:./sandbox` |
| `REF_DATA_DIR` | Where the files that are written go. | `/var/lib/reference` |
| `REF_KEYSTORE` | The key store with the signing, encryption and federation keys. | `${REF_CONFIG_LOCATION}/common/dummy.jks` |
| `REF_KEYSTORE_TYPE` | Its type, for example `JKS` or `PKCS12`. | `JKS` |
| `REF_KEYSTORE_PASSWORD` | Its password. | `secret` |
| `REF_SIGN_KEY_ALIAS`, `REF_SIGN_KEY_PASSWORD` | The EC signing key. | `sign`, `secret` |
| `REF_ENCRYPT_KEY_ALIAS`, `REF_ENCRYPT_KEY_PASSWORD` | The RSA encryption key. | `encrypt`, `secret` |
| `REF_FEDERATION_KEY_ALIAS`, `REF_FEDERATION_KEY_PASSWORD` | The federation key. | `federation`, `secret` |
| `REF_TLS_KEYSTORE` | The TLS key store. | `${REF_CONFIG_LOCATION}/common/dummy-tls.jks` |
| `REF_TLS_KEYSTORE_TYPE` | Its type. | `JKS` |
| `REF_TLS_KEYSTORE_PASSWORD` | Its password. | `secret` |
| `REF_TLS_KEY_ALIAS`, `REF_TLS_KEY_PASSWORD` | The TLS key. | `tls`, `secret` |
| `REF_SUBJECT_ID_SECRET` | The secret in the computation of the SAML NameID and the OIDC sub. | A test value |

A real deployment sets `REF_CONFIG_LOCATION` to, for example, `file:/etc/config`, and copies the layout below there.

## Layout

```
sandbox/
  application-sandbox.yml     the profile
  common/
    dummy.jks                 TEST KEYS: sign (EC P-256), encrypt (RSA 3072), federation (EC P-256)
    dummy-tls.jks             TEST KEY: tls (RSA 2048, self-signed, ref.sandbox.swedenconnect.se and localhost)
    users.yml                 the simulated users, a copy of the users of the service
  saml/
    metadata-signing.crt      the certificate of the Sandbox metadata service
  oidc/
    trust-anchor.jwks         the federation key of the Sandbox trust anchor
    tmi-loa.jwks              the federation keys of the trust mark issuer tmi-loa
    tmi-contracts.jwks        the federation keys of the trust mark issuer tmi-contracts
```

Written under `REF_DATA_DIR`:

```
audit/audit.log               the audit log
cache/                        the own trust marks and the OpenID Federation client cache
saml/sp-metadata-backup.xml   the backup of the SAML SP metadata
```

## The keys

The key stores are dummies, generated with fresh keys and self-signed certificates so that the setup can be started.
The password of the stores and every key is `secret`. A real deployment replaces them through the `REF_KEYSTORE` and
`REF_TLS_KEYSTORE` variables.

- `sign`, an EC key, signs SAML responses and assertions, and is the default OIDC signing key.
- `encrypt`, an RSA key, is the SAML encryption key and the OIDC decryption key.
- `federation` signs the OpenID Federation entity configuration and the SAML metadata.

## Where the federation files came from

- `saml/metadata-signing.crt` was downloaded from https://md.sandbox.swedenconnect.se/mdreg/pub/metadata-cert.crt and
  is the same certificate as the one on https://docs.swedenconnect.se/sandbox-pages/saml.html.
- `oidc/trust-anchor.jwks` holds the trust anchor federation key published in Section 5.3.1 of
  https://docs.swedenconnect.se/federation/oidf-structure.html.
- The trust mark issuers are not direct subordinates of the trust anchor. `tmi-loa` is registered under
  `https://fed.sandbox.swedenconnect.se/im-reg-sc`, and `tmi-contracts` under
  `https://fed.sandbox.swedenconnect.se/im-reg-sc-op`. The subordinate statement about each intermediate was fetched
  from the trust anchor's fetch endpoint and verified with the published trust anchor key, and the subordinate
  statement about each issuer was fetched from the intermediate's fetch endpoint and verified with the intermediate's
  key from the first statement. `oidc/tmi-loa.jwks` and `oidc/tmi-contracts.jwks` hold the `jwks` of those last
  statements. Fetched 2026-10-06.

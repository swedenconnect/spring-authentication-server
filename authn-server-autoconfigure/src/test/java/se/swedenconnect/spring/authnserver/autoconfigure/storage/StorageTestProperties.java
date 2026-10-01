/*
 * Copyright 2026 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.spring.authnserver.autoconfigure.storage;

/**
 * The properties of a server with both protocols, for the storage tests.
 *
 * @author Martin Lindström
 */
final class StorageTestProperties {

  static final String BASE_URL = "https://idp.example.com/auth";

  static final String SAML_CREDENTIALS = "authn-server.saml.credentials.default-credential.jks.";

  static final String OIDC_KEY = "authn-server.oidc.keys.signing[0].credential.jks.";

  static final String FEDERATION_KEY = "authn-server.oidc.federation.keys[0].credential.jks.";

  static final String[] SERVER = {
      "authn-server.base-url=" + BASE_URL,
      "authn-server.saml.enabled=true",
      SAML_CREDENTIALS + "store.location=classpath:credentials/idp-credentials.p12",
      SAML_CREDENTIALS + "store.password=secret",
      SAML_CREDENTIALS + "store.type=PKCS12",
      SAML_CREDENTIALS + "key.alias=sign",
      SAML_CREDENTIALS + "key.key-password=secret",
      "authn-server.saml.metadata-providers[0].location=classpath:metadata/sp-metadata.xml",
      "authn-server.oidc.enabled=true",
      OIDC_KEY + "store.location=classpath:credentials/oidc-keys.p12",
      OIDC_KEY + "store.password=secret",
      OIDC_KEY + "store.type=PKCS12",
      OIDC_KEY + "key.alias=rsa-sign",
      OIDC_KEY + "key.key-password=secret",
      "authn-server.oidc.federation.enabled=true",
      "authn-server.oidc.federation.authority-hints[0]=https://ia.example.com",
      "authn-server.entity-information.ui-info.display-names.sv=Exempel",
      "authn-server.entity-information.ui-info.logotypes[0].url=https://cdn.example.com/logo.svg",
      "authn-server.entity-information.organization.names.sv=Exempel AB",
      "authn-server.entity-information.organization.number=5561234567",
      "authn-server.entity-information.contact-persons.technical.email-addresses[0]=ops@example.com",
      FEDERATION_KEY + "store.location=classpath:credentials/oidc-keys.p12",
      FEDERATION_KEY + "store.password=secret",
      FEDERATION_KEY + "store.type=PKCS12",
      FEDERATION_KEY + "key.alias=rsa-sign",
      FEDERATION_KEY + "key.key-password=secret",
      "authn-server.oidc.federation.trust-marks[0].type=https://id.swedenconnect.se/loa/loa3",
      "authn-server.oidc.federation.trust-marks[0].issuer=https://tmi.example.com",
      "authn-server.oidc.federation.trust-marks[0].endpoint=http://localhost:1/trust_mark",
      "authn-server.oidc.federation.trust-marks[0].jwks=classpath:federation/tmi-jwks.json"
  };

  // Hidden constructor
  private StorageTestProperties() {
  }

}

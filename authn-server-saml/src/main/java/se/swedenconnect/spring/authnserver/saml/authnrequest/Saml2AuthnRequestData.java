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
package se.swedenconnect.spring.authnserver.saml.authnrequest;

import java.io.Serial;
import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.saml2.core.AuthnRequest;

import se.swedenconnect.opensaml.common.utils.SerializableOpenSamlObject;
import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.saml.nameid.NameIDGenerator;
import se.swedenconnect.spring.authnserver.saml.response.Saml2ResponseAttributes;

/**
 * The SAML data of a processed authentication request, which the response is built from. It is carried as the
 * protocol request data of the
 * {@link se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken
 * UserAuthenticationInputToken}.
 *
 * @param authnRequest the authentication request
 * @param responseAttributes where and how the response is sent
 * @param holderOfKey whether the request was received on a Holder-of-key endpoint
 * @param nameIdGenerator the generator for the {@code NameID} of the assertion
 * @param holderOfKeyCertificate the certificate that the client presented on the Holder-of-key endpoint, which the
 *     Holder-of-key subject confirmation is built from. {@code null} when the request was not a Holder-of-key request
 * @author Martin Lindström
 */
public record Saml2AuthnRequestData(@NonNull SerializableOpenSamlObject<AuthnRequest> authnRequest,
    @NonNull Saml2ResponseAttributes responseAttributes, boolean holderOfKey,
    @NonNull NameIDGenerator nameIdGenerator, @Nullable X509Certificate holderOfKeyCertificate)
    implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param authnRequest the authentication request
   * @param responseAttributes where and how the response is sent
   * @param holderOfKey whether the request was received on a Holder-of-key endpoint
   * @param nameIdGenerator the generator for the {@code NameID} of the assertion
   * @param holderOfKeyCertificate the client certificate for the Holder-of-key subject confirmation, required for a
   *     Holder-of-key request and ignored otherwise
   */
  public Saml2AuthnRequestData {
    Objects.requireNonNull(authnRequest, "authnRequest must not be null");
    Objects.requireNonNull(responseAttributes, "responseAttributes must not be null");
    Objects.requireNonNull(nameIdGenerator, "nameIdGenerator must not be null");
    if (holderOfKey) {
      Objects.requireNonNull(holderOfKeyCertificate, "holderOfKeyCertificate must be set for Holder-of-key");
    }
    else {
      holderOfKeyCertificate = null;
    }
  }

  /**
   * Gets the authentication request.
   *
   * @return the authentication request
   */
  public @NonNull AuthnRequest getAuthnRequest() {
    return this.authnRequest.get();
  }

}

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
package se.swedenconnect.spring.authnserver.saml.attributes.requested;

import java.util.Objects;
import java.util.Optional;

import org.jspecify.annotations.NonNull;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

/**
 * What a {@link RequestedAttributeProcessor} works from: the authentication request and the metadata of the Service
 * Provider that sent it.
 *
 * @param authnRequest the authentication request
 * @param spMetadata the metadata entry of the Service Provider
 * @author Martin Lindström
 */
public record RequestedAttributeContext(@NonNull AuthnRequest authnRequest, @NonNull EntityDescriptor spMetadata) {

  /**
   * Constructor.
   *
   * @param authnRequest the authentication request
   * @param spMetadata the metadata entry of the Service Provider
   */
  public RequestedAttributeContext {
    Objects.requireNonNull(authnRequest, "authnRequest must not be null");
    Objects.requireNonNull(spMetadata, "spMetadata must not be null");
  }

  /**
   * Gets the string that identifies the request in the logs.
   *
   * @return the log string
   */
  public @NonNull String getLogString() {
    return "entity-id: '%s', authn-request: '%s'".formatted(
        Optional.ofNullable(this.spMetadata.getEntityID()).orElse("unknown"),
        Optional.ofNullable(this.authnRequest.getID()).orElse("unknown"));
  }

}

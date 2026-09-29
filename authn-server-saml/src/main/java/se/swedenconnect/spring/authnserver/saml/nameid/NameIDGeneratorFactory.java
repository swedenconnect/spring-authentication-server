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
package se.swedenconnect.spring.authnserver.saml.nameid;

import jakarta.annotation.Nonnull;

import java.util.List;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatusException;

/**
 * Creates the {@link NameIDGenerator} to use for an authentication request. The generator is worked out from what the
 * request and the Service Provider metadata ask for, and from the Identity Provider policy.
 *
 * @author Martin Lindström
 */
public interface NameIDGeneratorFactory {

  /**
   * Gets the generator to use for the supplied request.
   *
   * @param authnRequest the authentication request
   * @param peerMetadata the metadata of the Service Provider that sent the request
   * @return a {@link NameIDGenerator}
   * @throws SamlErrorStatusException if the request asks for a {@code Format} that is not supported
   */
  @Nonnull
  NameIDGenerator getNameIDGenerator(final @Nonnull AuthnRequest authnRequest,
      final @Nonnull EntityDescriptor peerMetadata) throws SamlErrorStatusException;

  /**
   * Gets the {@code NameID} formats that the factory supports, the most preferred one first. They are declared in the
   * Identity Provider metadata.
   *
   * @return the supported formats
   */
  @Nonnull
  List<String> getSupportedFormats();

}

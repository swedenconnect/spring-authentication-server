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
package se.swedenconnect.spring.authnserver.saml.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.spring.authnserver.saml.metadata.Saml2MetadataHttpMessageConverter;

/**
 * A filter that publishes the metadata of the SAML Identity Provider. The metadata is signed and updated when needed,
 * according to how the {@link EntityDescriptorContainer} has been set up.
 *
 * @author Martin Lindström
 */
public class Saml2IdpMetadataEndpointFilter extends OncePerRequestFilter {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(Saml2IdpMetadataEndpointFilter.class);

  /** Media type for SAML metadata in XML format. */
  public static final MediaType APPLICATION_SAML_METADATA = new MediaType("application", "samlmetadata+xml");

  /** The request matcher for the metadata publishing endpoint. */
  private final RequestMatcher requestMatcher;

  /** The container holding the IdP metadata. */
  private final EntityDescriptorContainer entityDescriptorContainer;

  /** Converter for writing metadata. */
  private final Saml2MetadataHttpMessageConverter messageConverter = new Saml2MetadataHttpMessageConverter();

  /**
   * Constructor.
   *
   * @param entityDescriptorContainer the IdP metadata container
   * @param requestMatcher the request matcher for the metadata endpoint
   */
  public Saml2IdpMetadataEndpointFilter(final @NonNull EntityDescriptorContainer entityDescriptorContainer,
      final @NonNull RequestMatcher requestMatcher) {
    this.entityDescriptorContainer =
        Objects.requireNonNull(entityDescriptorContainer, "entityDescriptorContainer must not be null");
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void doFilterInternal(final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response, final @NonNull FilterChain filterChain)
      throws ServletException, IOException {

    if (!this.requestMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    log.debug("Request to download metadata from {}", request.getRemoteAddr());
    try {
      // Check if the metadata is up-to-date according to how the container was configured.
      //
      if (this.entityDescriptorContainer.updateRequired(true)) {
        log.debug("Metadata needs to be updated ...");
        this.entityDescriptorContainer.update(true);
        log.debug("Metadata was updated");
      }
      else {
        log.debug("Metadata is up-to-date, using cached metadata");
      }

      final String acceptHeader = request.getHeader("Accept");
      final MediaType contentType =
          acceptHeader != null && acceptHeader.contains(APPLICATION_SAML_METADATA.toString())
              ? APPLICATION_SAML_METADATA
              : MediaType.APPLICATION_XML;

      final ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
      this.messageConverter.write(this.entityDescriptorContainer.getDescriptor(), contentType, httpResponse);
    }
    catch (final SignatureException | MarshallingException e) {
      log.error("Failed to return valid metadata", e);
      throw new IOException("Failed to produce SAML metadata", e);
    }
  }

}

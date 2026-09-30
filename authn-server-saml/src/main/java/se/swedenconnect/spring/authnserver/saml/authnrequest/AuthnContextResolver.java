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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatus;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatusException;

/**
 * Resolves the {@code RequestedAuthnContext} of an authentication request into the authentication context URIs that
 * are acceptable, in the requester's order of preference.
 * <p>
 * The {@code exact} comparison is always supported and gives the requested URIs. The {@code minimum}, {@code better}
 * and {@code maximum} comparisons are supported when a mapping for them has been configured. Each mapping maps a
 * requested URI to the URIs that it means for that comparison. For example, a minimum mapping of {@code loa3} to
 * {@code [loa3, loa4]} means that a request for at least {@code loa3} accepts {@code loa3} and {@code loa4}.
 * </p>
 *
 * @author Martin Lindström
 */
public class AuthnContextResolver {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(AuthnContextResolver.class);

  /** The mapping for minimum comparison. */
  private Map<String, List<String>> minimumMapping;

  /** The mapping for better comparison. */
  private Map<String, List<String>> betterMapping;

  /** The mapping for maximum comparison. */
  private Map<String, List<String>> maximumMapping;

  /**
   * Resolves the requested authentication context.
   *
   * @param requestedAuthnContext the requested authentication context, or {@code null}
   * @param logString the log string of the request
   * @return the acceptable authentication context URIs, empty if none were requested
   * @throws SamlErrorStatusException if the requested authentication context cannot be resolved
   */
  public @NonNull List<String> resolve(final @Nullable RequestedAuthnContext requestedAuthnContext,
      final @NonNull String logString) throws SamlErrorStatusException {

    if (requestedAuthnContext == null) {
      return List.of();
    }
    if (requestedAuthnContext.getAuthnContextClassRefs().isEmpty()
        && !requestedAuthnContext.getAuthnContextDeclRefs().isEmpty()) {
      throw invalid("AuthnContextDeclRefs not supported in RequestedAuthnContext", logString);
    }
    final List<String> requestedUris = requestedAuthnContext.getAuthnContextClassRefs().stream()
        .map(XSURI::getURI)
        .toList();

    final AuthnContextComparisonTypeEnumeration comparison = requestedAuthnContext.getComparison();
    if (comparison == null || AuthnContextComparisonTypeEnumeration.EXACT == comparison) {
      return requestedUris;
    }
    if (AuthnContextComparisonTypeEnumeration.MINIMUM == comparison) {
      if (this.minimumMapping == null) {
        throw invalid("minimum comparison for RequestedAuthnContext is not supported", logString);
      }
      final List<String> resolved = new ArrayList<>();
      for (final String uri : requestedUris) {
        final List<String> mappings = this.minimumMapping.get(uri);
        if (mappings != null) {
          mappings.stream().filter(u -> !resolved.contains(u)).forEach(resolved::add);
        }
      }
      if (resolved.isEmpty()) {
        throw invalid("no configuration for minimum comparison URIs in RequestedAuthnContext", logString);
      }
      log.debug("Resolved minimum comparison URIs: {} [{}]", resolved, logString);
      return resolved;
    }
    if (AuthnContextComparisonTypeEnumeration.BETTER == comparison) {
      if (this.betterMapping == null) {
        throw invalid("better comparison for RequestedAuthnContext is not supported", logString);
      }
      List<String> resolved = null;
      for (final String uri : requestedUris) {
        final List<String> mappings = this.betterMapping.getOrDefault(uri, List.of());
        if (resolved == null) {
          resolved = new ArrayList<>(mappings);
        }
        else {
          resolved.retainAll(mappings);
        }
      }
      if (resolved == null || resolved.isEmpty()) {
        throw invalid("no configuration for better comparison URIs in RequestedAuthnContext", logString);
      }
      log.debug("Resolved better comparison URIs: {} [{}]", resolved, logString);
      return resolved;
    }
    if (AuthnContextComparisonTypeEnumeration.MAXIMUM == comparison) {
      if (this.maximumMapping == null) {
        throw invalid("maximum comparison for RequestedAuthnContext is not supported", logString);
      }
      final List<String> resolved = new ArrayList<>();
      for (final String uri : requestedUris) {
        final List<String> mappings = this.maximumMapping.get(uri);
        if (mappings != null) {
          mappings.stream().filter(u -> !resolved.contains(u)).forEach(resolved::add);
        }
      }
      resolved.removeAll(requestedUris);
      if (resolved.isEmpty()) {
        throw invalid("no configuration for maximum comparison URIs in RequestedAuthnContext", logString);
      }
      log.debug("Resolved maximum comparison URIs: {} [{}]", resolved, logString);
      return resolved;
    }
    throw invalid("unknown comparison in RequestedAuthnContext", logString);
  }

  /**
   * Assigns the mapping for minimum comparison.
   *
   * @param minimumMapping the mapping, or {@code null} if minimum comparison is not supported
   */
  public void setMinimumMapping(final @Nullable Map<String, List<String>> minimumMapping) {
    this.minimumMapping = minimumMapping;
  }

  /**
   * Assigns the mapping for better comparison.
   *
   * @param betterMapping the mapping, or {@code null} if better comparison is not supported
   */
  public void setBetterMapping(final @Nullable Map<String, List<String>> betterMapping) {
    this.betterMapping = betterMapping;
  }

  /**
   * Assigns the mapping for maximum comparison.
   *
   * @param maximumMapping the mapping, or {@code null} if maximum comparison is not supported
   */
  public void setMaximumMapping(final @Nullable Map<String, List<String>> maximumMapping) {
    this.maximumMapping = maximumMapping;
  }

  /**
   * Creates the exception for an invalid requested authentication context, and logs it.
   *
   * @param reason the reason
   * @param logString the log string of the request
   * @return a {@link SamlErrorStatusException}
   */
  private static @NonNull SamlErrorStatusException invalid(final @NonNull String reason,
      final @NonNull String logString) {
    final String msg = "Invalid AuthnRequest - " + reason;
    log.info("{} [{}]", msg, logString);
    return new SamlErrorStatusException(SamlErrorStatus.INVALID_REQUEST, SamlErrorStatus.INVALID_REQUEST_MESSAGE_CODE,
        msg);
  }

}

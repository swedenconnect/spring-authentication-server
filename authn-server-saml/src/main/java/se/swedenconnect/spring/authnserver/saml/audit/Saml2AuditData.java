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
package se.swedenconnect.spring.authnserver.saml.audit;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.core.Subject;

import se.swedenconnect.spring.authnserver.audit.AuditAttribute;
import se.swedenconnect.spring.authnserver.audit.ProtocolAuditData;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeValues;
import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * Creates the SAML part of the audit events from the SAML messages.
 *
 * @author Martin Lindström
 */
public final class Saml2AuditData {

  /** The name of the object describing the authentication request. */
  public static final String AUTHN_REQUEST = "authn_request";

  /** The name of the object describing the response. */
  public static final String RESPONSE = "response";

  /** The name of the object describing the assertion, nested in the response. */
  public static final String ASSERTION = "assertion";

  /**
   * Creates the {@code authn_request} object from a received authentication request.
   *
   * @param token the authentication request token
   * @return the protocol-specific data
   */
  public static @NonNull ProtocolAuditData authnRequest(final @NonNull Saml2AuthnRequestAuthenticationToken token) {
    final AuthnRequest authnRequest = token.getAuthnRequest();
    return ProtocolAuditData.builder(AUTHN_REQUEST)
        .member("id", authnRequest.getID())
        .member("issuer", token.getEntityId())
        .member("destination", authnRequest.getDestination())
        .member("binding", token.getBindingUri())
        .member("assertion_consumer_service_url", Optional.ofNullable(token.getAssertionConsumerServiceUrl())
            .orElseGet(authnRequest::getAssertionConsumerServiceURL))
        .member("authn_context_class_refs", Optional.ofNullable(authnRequest.getRequestedAuthnContext())
            .map(RequestedAuthnContext::getAuthnContextClassRefs)
            .map(refs -> refs.stream().map(AuthnContextClassRef::getURI).filter(Objects::nonNull).toList())
            .orElse(null))
        .member("force_authn", Boolean.TRUE.equals(authnRequest.isForceAuthn()))
        .member("is_passive", Boolean.TRUE.equals(authnRequest.isPassive()))
        .member("relay_state", token.getRelayState())
        .member("signed", isSigned(authnRequest, token.getHttpServletRequest()))
        .member("holder_of_key", token.isHolderOfKey())
        .build();
  }

  /**
   * Creates the {@code response} object for a success response.
   *
   * @param response the response
   * @param assertion the assertion of the response, before it was encrypted
   * @param relayState the relay state, or {@code null}
   * @return the protocol-specific data
   */
  public static @NonNull ProtocolAuditData successResponse(final @NonNull Response response,
      final @NonNull Assertion assertion, final @Nullable String relayState) {

    final ProtocolAuditData.Builder assertionData = ProtocolAuditData.builder(ASSERTION)
        .member("id", assertion.getID())
        .member("signed", assertion.isSigned())
        .member("encrypted", !response.getEncryptedAssertions().isEmpty());
    final NameID nameId = Optional.ofNullable(assertion.getSubject()).map(Subject::getNameID).orElse(null);
    if (nameId != null) {
      assertionData.member("subject_id", nameId.getValue())
          .member("subject_id_format", nameId.getFormat());
    }
    final AuthnStatement statement =
        assertion.getAuthnStatements().isEmpty() ? null : assertion.getAuthnStatements().getFirst();
    if (statement != null) {
      assertionData.member("authn_instant", statement.getAuthnInstant());
      if (statement.getAuthnContext() != null) {
        assertionData.member("authn_context_class_ref",
            Optional.ofNullable(statement.getAuthnContext().getAuthnContextClassRef())
                .map(AuthnContextClassRef::getURI)
                .orElse(null));
        assertionData.member("authenticating_authorities",
            statement.getAuthnContext().getAuthenticatingAuthorities().stream()
                .map(AuthenticatingAuthority::getURI)
                .filter(Objects::nonNull)
                .toList());
      }
    }
    return responseBuilder(response, relayState)
        .member(assertionData.build())
        .build();
  }

  /**
   * Creates the {@code response} object for an error response.
   *
   * @param response the error response
   * @param relayState the relay state, or {@code null}
   * @return the protocol-specific data
   */
  public static @NonNull ProtocolAuditData errorResponse(final @NonNull Response response,
      final @Nullable String relayState) {
    final ProtocolAuditData.Builder builder = responseBuilder(response, relayState);
    final Status status = response.getStatus();
    if (status != null) {
      final StatusCode code = status.getStatusCode();
      if (code != null) {
        builder.member("status_code", code.getValue())
            .member("subordinate_status_code",
                Optional.ofNullable(code.getStatusCode()).map(StatusCode::getValue).orElse(null));
      }
      builder.member("status_message",
          Optional.ofNullable(status.getStatusMessage()).map(StatusMessage::getValue).orElse(null));
    }
    return builder.build();
  }

  /**
   * Gets the attributes of an assertion, by their SAML names.
   *
   * @param assertion the assertion, before it was encrypted
   * @return the attributes
   */
  public static @NonNull List<AuditAttribute> releasedAttributes(final @NonNull Assertion assertion) {
    return assertion.getAttributeStatements().stream()
        .flatMap(s -> s.getAttributes().stream())
        .map(a -> new AuditAttribute(a.getName(), SamlAttributeValues.getStringValues(a)))
        .toList();
  }

  /**
   * Creates a builder for the {@code response} object holding the members that success and error responses share.
   *
   * @param response the response
   * @param relayState the relay state, or {@code null}
   * @return a builder
   */
  private static ProtocolAuditData.@NonNull Builder responseBuilder(final @NonNull Response response,
      final @Nullable String relayState) {
    return ProtocolAuditData.builder(RESPONSE)
        .member("id", response.getID())
        .member("in_response_to", response.getInResponseTo())
        .member("destination", response.getDestination())
        .member("issued_at", response.getIssueInstant())
        .member("signed", response.isSigned())
        .member("relay_state", relayState);
  }

  /**
   * Tells whether an authentication request was signed, either with an XML signature or, for the redirect binding, in
   * the query string.
   *
   * @param authnRequest the authentication request
   * @param request the HTTP request, or {@code null}
   * @return {@code true} if the request was signed and {@code false} otherwise
   */
  private static boolean isSigned(final @NonNull AuthnRequest authnRequest,
      final @Nullable HttpServletRequest request) {
    return authnRequest.isSigned() || (request != null && request.getParameter("Signature") != null);
  }

  // Hidden constructor
  private Saml2AuditData() {
  }

}

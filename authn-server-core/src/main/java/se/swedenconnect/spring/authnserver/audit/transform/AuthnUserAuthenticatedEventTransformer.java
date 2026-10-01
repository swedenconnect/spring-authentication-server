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
package se.swedenconnect.spring.authnserver.audit.transform;

import java.io.Serializable;
import java.util.List;
import java.util.Locale;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.audit.value.AuditValue;
import se.swedenconnect.spring.audit.value.MapAuditValue;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.audit.AuditAttribute;
import se.swedenconnect.spring.authnserver.audit.AuthnAuditTypes;
import se.swedenconnect.spring.authnserver.audit.events.AuthnUserAuthenticatedEvent;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationUse;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Transforms an {@link AuthnUserAuthenticatedEvent} into an audit event of the type
 * {@code authn_user_authenticated}. The data is the {@code requester} object, the protocol-specific
 * {@code authn_request} object, the {@code user_authentication} object, and the {@code attributes} list holding every
 * attribute that the authenticator delivered, by their protocol-neutral names.
 *
 * @author Martin Lindström
 */
public class AuthnUserAuthenticatedEventTransformer
    extends AbstractAuthnEventTransformer<AuthnUserAuthenticatedEvent> {

  /** The name of the object describing the authentication. */
  public static final String USER_AUTHENTICATION = "user_authentication";

  /** The name of the list of the attributes that the authenticator delivered. */
  public static final String ATTRIBUTES = "attributes";

  /**
   * Constructor.
   */
  public AuthnUserAuthenticatedEventTransformer() {
    super(AuthnUserAuthenticatedEvent.class, AuthnAuditTypes.AUTHN_USER_AUTHENTICATED);
  }

  /**
   * Adds the {@code user_authentication} object and the {@code attributes} list.
   */
  @Override
  protected @NonNull List<AuditValue<? extends Serializable>> getDataFields(
      final @NonNull AuthnUserAuthenticatedEvent event) {
    final List<AuditValue<? extends Serializable>> fields = super.getDataFields(event);
    fields.add(this.userAuthentication(event));
    fields.add(attributes(ATTRIBUTES, event.getAuthentication().getAuthenticatedUser().getAttributes().stream()
        .map(AuditAttribute::of)
        .toList()));
    return fields;
  }

  /**
   * Creates the {@code user_authentication} object.
   *
   * @param event the event
   * @return a {@link MapAuditValue}
   */
  protected @NonNull MapAuditValue userAuthentication(final @NonNull AuthnUserAuthenticatedEvent event) {
    final UserAuthentication authentication = event.getAuthentication();
    final AuthenticatedUser user = authentication.getAuthenticatedUser();
    final MapAuditValue.Builder builder = MapAuditValue.builder()
        .name(USER_AUTHENTICATION)
        .value("authn_instant", user.getAuthnInstant())
        .value("acr", user.getAuthnContextUri());
    final String authority = getAuthenticatingAuthority(user);
    if (authority != null) {
      builder.value("authenticating_authority", authority);
    }
    builder.value("client_ip_address", user.getClientIpAddress())
        .value("sign_message_displayed", user.isSignMessageDisplayed())
        .value("allowed_to_reuse", authentication.isReuseForSso())
        .value("sso", event.isSso());
    final AuthenticationUse original = authentication.getUsageTrack().getOriginalAuthentication();
    if (event.isSso() && original != null) {
      final MapAuditValue.Builder sso = MapAuditValue.builder()
          .name("sso_information")
          .value("original_protocol", original.protocol().name().toLowerCase(Locale.ROOT))
          .value("original_requester", original.requester());
      if (original.requestId() != null) {
        sso.value("original_request_id", original.requestId());
      }
      builder.value(sso.build());
    }
    return builder.build();
  }

  /**
   * Gets the authenticating authority, the service that authenticated the user when the server proxies the
   * authentication.
   *
   * @param user the user
   * @return the authenticating authority, or {@code null}
   */
  private static @Nullable String getAuthenticatingAuthority(final @NonNull AuthenticatedUser user) {
    final GenericAttribute<?> attribute = user.getAttribute(AttributeIdentifiers.AUTHENTICATION_PROVIDER);
    return attribute != null && !attribute.getValues().isEmpty() ? String.valueOf(attribute.getValue()) : null;
  }

}

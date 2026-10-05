/*
 * Copyright 2016-2026 Sweden Connect
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
package se.swedenconnect.spring.authnserver.service.authn;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

import se.oidc.nimbus.claims.ScopeConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.AbstractUserRedirectAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.ResumedAuthenticationToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.service.users.SimulatedUser;

/**
 * The authentication provider of the simulated authentication. The user is sent to the user picker, served by
 * {@link SimulatedAuthenticationController}, and the selected user is turned into the authentication result when the
 * flow resumes.
 *
 * @author Martin Lindström
 */
public class SimulatedAuthenticationProvider extends AbstractUserRedirectAuthenticationProvider {

  /** The attributes that the provider delivers. */
  private static final List<String> SUPPORTED_ATTRIBUTES = List.of(
      AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER,
      AttributeIdentifiers.GIVEN_NAME,
      AttributeIdentifiers.SURNAME,
      AttributeIdentifiers.DISPLAY_NAME,
      AttributeIdentifiers.DATE_OF_BIRTH);

  /**
   * The OpenID Connect scopes that the provider offers. The scopes of signature services are scopes without claims,
   * and are therefore only offered when they are declared.
   */
  private static final List<String> SUPPORTED_SCOPES = List.of(
      OIDCScopeValue.OPENID.getValue(),
      OIDCScopeValue.PROFILE.getValue(),
      ScopeConstants.NATURAL_PERSON_INFO.getValue(),
      ScopeConstants.NATURAL_PERSON_PERSONAL_NUMBER.getValue(),
      ScopeConstants.SIGN.getValue(),
      ScopeConstants.SIGN_APPROVAL.getValue());

  /** The name of the provider. */
  private final String name;

  /** The supported levels of assurance. */
  private final List<String> supportedAuthnContextUris;

  /** The declared SAML entity categories. */
  private final List<String> entityCategories;

  /**
   * Constructor.
   *
   * @param name the name of the provider
   * @param authnPath the path of the user picker, where the user is sent for authentication
   * @param resumeAuthnPath the path that the user is sent back to after the authentication
   * @param supportedAuthnContextUris the supported levels of assurance
   * @param entityCategories the SAML entity categories that the provider declares, may be {@code null}
   */
  public SimulatedAuthenticationProvider(final @NonNull String name, final @NonNull String authnPath,
      final @NonNull String resumeAuthnPath, final @NonNull List<String> supportedAuthnContextUris,
      final @Nullable List<String> entityCategories) {
    super(authnPath, resumeAuthnPath);
    if (!StringUtils.hasText(name)) {
      throw new IllegalArgumentException("name must be set");
    }
    this.name = name;
    if (supportedAuthnContextUris == null || supportedAuthnContextUris.isEmpty()) {
      throw new IllegalArgumentException("supportedAuthnContextUris must be set and not be empty");
    }
    this.supportedAuthnContextUris = List.copyOf(supportedAuthnContextUris);
    this.entityCategories = entityCategories != null ? List.copyOf(entityCategories) : List.of();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String getName() {
    return this.name;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<String> getSupportedAuthnContextUris() {
    return this.supportedAuthnContextUris;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<String> getEntityCategories() {
    return this.entityCategories;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<String> getSupportedAttributes() {
    return SUPPORTED_ATTRIBUTES;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<String> getSupportedScopes() {
    return SUPPORTED_SCOPES;
  }

  /** {@inheritDoc} */
  @Override
  public boolean supportsUserAuthenticationToken(final @Nullable Authentication authentication) {
    return authentication instanceof SimulatedAuthenticationToken;
  }

  /**
   * Turns the user that was selected in the user picker into the authentication result.
   */
  @Override
  protected @NonNull UserAuthentication createUserAuthentication(final @NonNull ResumedAuthenticationToken token)
      throws AuthenticationErrorException {

    if (!(token.getAuthnToken() instanceof final SimulatedAuthenticationToken simulated)) {
      throw new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED,
          "The simulated authentication delivered no user");
    }
    final SimulatedUser user = simulated.getUser();

    final List<GenericAttribute<?>> attributes = new ArrayList<>();
    attributes.add(GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER,
        Objects.requireNonNull(user.getPersonalNumber(), "personalNumber must not be null")));
    addIfPresent(attributes, AttributeIdentifiers.GIVEN_NAME, user.getGivenName());
    addIfPresent(attributes, AttributeIdentifiers.SURNAME, user.getSurname());
    addIfPresent(attributes, AttributeIdentifiers.DISPLAY_NAME, user.getDisplayName());
    final LocalDate dateOfBirth = parseDate(user.getDateOfBirth());
    if (dateOfBirth != null) {
      attributes.add(GenericAttribute.of(AttributeIdentifiers.DATE_OF_BIRTH, dateOfBirth));
    }

    final AuthenticatedUser authenticatedUser = new AuthenticatedUser(attributes,
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, simulated.getLoa(), simulated.getAuthnInstant(),
        simulated.getClientIpAddress());
    if (simulated.isSignMessageDisplayed()) {
      authenticatedUser.setSignMessageDisplayed(true, simulated.getSignMessageLanguage());
    }
    return new UserAuthentication(authenticatedUser);
  }

  /**
   * Adds a string attribute if it has a value.
   *
   * @param attributes the attributes to add to
   * @param identifier the attribute identifier
   * @param value the value, may be {@code null}
   */
  private static void addIfPresent(final @NonNull List<GenericAttribute<?>> attributes,
      final @NonNull String identifier, final @Nullable String value) {
    if (StringUtils.hasText(value)) {
      attributes.add(GenericAttribute.of(identifier, value));
    }
  }

  /**
   * Parses a date of birth.
   *
   * @param date the date (YYYY-MM-DD), may be {@code null}
   * @return the date, or {@code null} if it is not given or not valid
   */
  private static @Nullable LocalDate parseDate(final @Nullable String date) {
    if (!StringUtils.hasText(date)) {
      return null;
    }
    try {
      return LocalDate.parse(date);
    }
    catch (final DateTimeParseException e) {
      return null;
    }
  }

}

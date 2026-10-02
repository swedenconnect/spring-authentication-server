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

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import se.oidc.nimbus.claims.ScopeConstants;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.AbstractAuthenticationController;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectForAuthenticationToken;
import se.swedenconnect.spring.authnserver.autoconfigure.ConfiguredAuthnServer;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.message.GenericMessage;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;
import se.swedenconnect.spring.authnserver.message.GenericUserMessage;
import se.swedenconnect.spring.authnserver.message.LocalizedMessage;
import se.swedenconnect.spring.authnserver.oidc.authentication.OidcAuthenticationRequirements;
import se.swedenconnect.spring.authnserver.oidc.scope.BuiltInScopes;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.saml.authentication.SamlAuthenticationRequirements;
import se.swedenconnect.spring.authnserver.service.authn.model.SelectedUserModel;
import se.swedenconnect.spring.authnserver.service.authn.model.UiModel;
import se.swedenconnect.spring.authnserver.service.config.CookieGenerator;
import se.swedenconnect.spring.authnserver.service.config.ReferenceConfiguration;
import se.swedenconnect.spring.authnserver.service.config.UnrecoverableErrorViewResolver;
import se.swedenconnect.spring.authnserver.service.config.UiProperties;
import se.swedenconnect.spring.authnserver.service.message.MessageHtmlConverter;
import se.swedenconnect.spring.authnserver.service.message.MessageProcessingException;
import se.swedenconnect.spring.authnserver.service.users.SimulatedUser;
import se.swedenconnect.spring.authnserver.service.users.SimulatedUsers;

/**
 * The user picker: the pages of the simulated authentication.
 * <p>
 * The user is sent here by {@link SimulatedAuthenticationProvider} with the identifier of the authentication in the
 * {@code authnId} parameter, chooses a user and a level of assurance, and is sent back into the flow. The same pages
 * serve SAML and OpenID Connect requests.
 * </p>
 *
 * @author Martin Lindström
 */
@Controller
@RequestMapping("${authn-server-reference.authn.authn-path}")
public class SimulatedAuthenticationController
    extends AbstractAuthenticationController<SimulatedAuthenticationProvider> {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(SimulatedAuthenticationController.class);

  /** The errors that a tester may simulate. */
  public static final List<AuthenticationError> SIMULATED_ERRORS = List.of(
      AuthenticationError.AUTHN_FAILED,
      AuthenticationError.CANCEL,
      AuthenticationError.FRAUD,
      AuthenticationError.POSSIBLE_FRAUD,
      AuthenticationError.UNKNOWN_PRINCIPAL,
      AuthenticationError.NO_AUTHN_CONTEXT,
      AuthenticationError.NOT_AUTHORIZED,
      AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED);

  /** The value that the user list posts when no user is selected. */
  private static final String NO_USER = "NONE";

  /** Separates the user and the level of assurance in the cookie of the last selection. */
  private static final String SELECTION_SEPARATOR = "#";

  /** The authentication provider. */
  private final SimulatedAuthenticationProvider provider;

  /** The simulated users. */
  private final SimulatedUsers users;

  /** The languages of the pages. */
  private final UiProperties ui;

  /** Converts the sign and user messages into HTML. */
  private final MessageHtmlConverter messageConverter;

  /** Remembers the last selected user and level of assurance. */
  private final CookieGenerator selectedUserCookie;

  /** Holds the users that the tester has added. */
  private final CookieGenerator savedUsersCookie;

  /** Gives the client registry, for the names and logotypes of the requesters. */
  private final ObjectProvider<ConfiguredAuthnServer> configuredServer;

  /**
   * Constructor.
   *
   * @param provider the authentication provider
   * @param users the simulated users
   * @param ui the languages of the pages
   * @param messageConverter converts the sign and user messages into HTML
   * @param selectedUserCookie remembers the last selected user and level of assurance
   * @param savedUsersCookie holds the users that the tester has added
   * @param configuredServer gives the client registry
   */
  public SimulatedAuthenticationController(final @NonNull SimulatedAuthenticationProvider provider,
      final @NonNull SimulatedUsers users, final @NonNull UiProperties ui,
      final @NonNull MessageHtmlConverter messageConverter,
      @Qualifier(ReferenceConfiguration.SELECTED_USER_COOKIE) final @NonNull CookieGenerator selectedUserCookie,
      @Qualifier(ReferenceConfiguration.SAVED_USERS_COOKIE) final @NonNull CookieGenerator savedUsersCookie,
      final @NonNull ObjectProvider<ConfiguredAuthnServer> configuredServer) {
    this.provider = Objects.requireNonNull(provider, "provider must not be null");
    this.users = Objects.requireNonNull(users, "users must not be null");
    this.ui = Objects.requireNonNull(ui, "ui must not be null");
    this.messageConverter = Objects.requireNonNull(messageConverter, "messageConverter must not be null");
    this.selectedUserCookie = Objects.requireNonNull(selectedUserCookie, "selectedUserCookie must not be null");
    this.savedUsersCookie = Objects.requireNonNull(savedUsersCookie, "savedUsersCookie must not be null");
    this.configuredServer = Objects.requireNonNull(configuredServer, "configuredServer must not be null");
  }

  /**
   * Shows the user picker.
   *
   * @param request the HTTP servlet request
   * @return a {@link ModelAndView}
   */
  @GetMapping
  public @NonNull ModelAndView authenticate(final @NonNull HttpServletRequest request) {

    final RedirectForAuthenticationToken token = this.getInputToken(request);
    final UserAuthenticationInputToken inputToken = token.getAuthnInputToken();
    final AuthenticationRequirements requirements = inputToken.getAuthnRequirements();
    final String language = LocaleContextHolder.getLocale().getLanguage();

    final List<SimulatedUser> users = this.users.getUsers(this.getSavedUsers(request));
    final UiModel uiModel = new UiModel();

    final RequesterDisplay display = this.getRequesterDisplay(inputToken, language);
    uiModel.setSpDisplayName(display.displayName());
    uiModel.setSpLogoUrl(display.logoUrl());

    // The user and level of assurance that were selected the last time ...
    //
    final String[] lastSelection = this.getLastSelection(request);
    uiModel.setSelectedUser(lastSelection[0]);
    uiModel.setSelectedAuthnContextUri(lastSelection[1]);

    // A requested personal identity number locks the selection, provided that the user is known ...
    //
    final String requestedUser = getRequestedPersonalIdentityNumber(requirements);
    if (requestedUser != null && users.stream().anyMatch(u -> requestedUser.equals(u.getPersonalNumber()))) {
      uiModel.setSelectedUser(requestedUser);
      uiModel.setFixedSelectedUser(true);
    }

    uiModel.setPossibleAuthnContextUris(token.getAuthnContextUris());
    uiModel.setSignature(isSignatureService(requirements));

    // The sign message ...
    //
    final GenericSignMessage signMessage = requirements.getSignMessage();
    if (signMessage != null) {
      final LocalizedMessage message = selectMessage(signMessage, language);
      try {
        uiModel.setSignMessage(this.messageConverter.toHtml(message, signMessage.getMimeType()));
      }
      catch (final MessageProcessingException e) {
        log.info("The sign message cannot be displayed: {} [{}]", e.getMessage(), inputToken.getLogString());
        return this.complete(request, new AuthenticationErrorException(AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED,
            "The sign message cannot be displayed - " + e.getMessage()));
      }
    }

    // The user message, which is not shown together with a sign message ...
    //
    final GenericUserMessage userMessage = requirements.getUserMessage();
    if (userMessage != null && uiModel.getSignMessage() == null) {
      final LocalizedMessage message = userMessage.getMessage(language);
      if (message != null) {
        try {
          uiModel.setUserMessage(this.messageConverter.toHtml(message, userMessage.getMimeType()));
        }
        catch (final MessageProcessingException e) {
          log.info("The user message is not displayed: {} [{}]", e.getMessage(), inputToken.getLogString());
        }
      }
    }

    final ModelAndView mav = new ModelAndView("simulated");
    mav.addObject("users", users);
    mav.addObject("ui", uiModel);
    mav.addObject("result", new SelectedUserModel());
    mav.addObject("authnId", token.getAuthnId());
    mav.addObject("errors", SIMULATED_ERRORS);
    return mav;
  }

  /**
   * Receives the result of the user picker and hands it to the provider.
   *
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param action what the tester chose: {@code ok}, {@code cancel} or {@code error}
   * @param result what the user picker posted
   * @return a {@link ModelAndView}
   */
  @PostMapping("/complete")
  public @NonNull ModelAndView complete(final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response, @RequestParam("action") final @NonNull String action,
      @ModelAttribute("result") final @NonNull SelectedUserModel result) {

    final RedirectForAuthenticationToken token = this.getInputToken(request);
    final String logString = token.getAuthnInputToken().getLogString();

    if ("cancel".equals(action)) {
      log.info("The simulated authentication was cancelled [{}]", logString);
      return this.cancel(request);
    }
    if ("error".equals(action)) {
      final AuthenticationError error = SIMULATED_ERRORS.stream()
          .filter(e -> e.name().equals(result.getError()))
          .findFirst()
          .orElse(AuthenticationError.AUTHN_FAILED);
      final String description = StringUtils.hasText(result.getErrorMessage())
          ? result.getErrorMessage()
          : "Simulated error";
      log.info("Simulated error {} [{}]", error, logString);
      return this.complete(request, new AuthenticationErrorException(error, description));
    }

    final String loa = result.getLoa();
    if (loa == null || !token.getAuthnContextUris().contains(loa)) {
      log.info("The selected level of assurance '{}' is not among the possible ones {} [{}]",
          loa, token.getAuthnContextUris(), logString);
      return this.complete(request, new AuthenticationErrorException(AuthenticationError.AUTHN_FAILED,
          "The selected level of assurance is not among the possible ones"));
    }

    final SimulatedUser user = this.processSelectedUser(request, response, result);
    if (user == null) {
      log.info("No known user was selected in the simulated authentication [{}]", logString);
      return this.complete(request, new AuthenticationErrorException(AuthenticationError.UNKNOWN_PRINCIPAL,
          "No known user was selected"));
    }
    this.selectedUserCookie.addCookie(user.getPersonalNumber() + SELECTION_SEPARATOR + loa, response);

    final SimulatedAuthenticationToken authnToken =
        new SimulatedAuthenticationToken(user, loa, Instant.now(), request.getRemoteAddr());
    final GenericSignMessage signMessage = token.getAuthnInputToken().getAuthnRequirements().getSignMessage();
    if (signMessage != null && result.isSignMessageDisplayed()) {
      authnToken.setSignMessageDisplayed(
          selectMessage(signMessage, LocaleContextHolder.getLocale().getLanguage()).language());
    }
    log.debug("Simulated authentication completed at '{}' [{}]", loa, logString);
    return this.complete(request, authnToken);
  }

  /**
   * Adds the languages that the page may be switched to, that is, all languages but the current one.
   *
   * @param model the model
   */
  @ModelAttribute
  public void addCommonAttributes(final @NonNull Model model) {
    final Locale locale = LocaleContextHolder.getLocale();
    model.addAttribute("languages", this.ui.getLanguages().stream()
        .filter(l -> !locale.getLanguage().equals(l.getTag()))
        .toList());
    model.addAttribute("authnPath", this.provider.getAuthnPath());
  }

  /**
   * Shows the error page when the user picker is reached without an authentication in progress, for example when the
   * session has expired.
   *
   * @param error the error
   * @return a {@link ModelAndView}
   */
  @ExceptionHandler(UnrecoverableErrorException.class)
  public @NonNull ModelAndView unrecoverableError(final @NonNull UnrecoverableErrorException error) {
    log.info("The simulated authentication cannot continue: {}", error.getMessage());
    final ModelAndView mav = new ModelAndView(UnrecoverableErrorViewResolver.VIEW_NAME, HttpStatus.BAD_REQUEST);
    mav.addObject("idpErrorMessageCode", error.getMessageCode());
    mav.addObject("idpErrorDescription", error.getError().getDescription());
    return mav;
  }

  /** {@inheritDoc} */
  @Override
  protected @NonNull SimulatedAuthenticationProvider getProvider() {
    return this.provider;
  }

  /**
   * Finds the selected user: a user from the list, a user that the tester has added earlier, or a user that the tester
   * enters now, which is then added to the saved users.
   *
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param result what the user picker posted
   * @return the user, or {@code null} if no known user was selected
   */
  private @Nullable SimulatedUser processSelectedUser(final @NonNull HttpServletRequest request,
      final @NonNull HttpServletResponse response, final @NonNull SelectedUserModel result) {

    final String personalNumber = result.getPersonalIdentityNumber();
    if (personalNumber == null) {
      return null;
    }
    final List<SimulatedUser> savedUsers = this.getSavedUsers(request);
    final SimulatedUser user = this.users.findUser(personalNumber, savedUsers);
    if (user != null || !result.isCustom()) {
      return user;
    }
    final SimulatedUser custom = new SimulatedUser();
    custom.setPersonalNumber(personalNumber);
    custom.setGivenName(Objects.requireNonNull(result.getGivenName()).trim());
    custom.setSurname(Objects.requireNonNull(result.getSurname()).trim());
    this.savedUsersCookie.addCookie(SimulatedUser.encodeList(SimulatedUsers.addSavedUser(custom, savedUsers)),
        response);
    return custom;
  }

  /**
   * Gets the users that the tester has added.
   *
   * @param request the HTTP servlet request
   * @return the saved users
   */
  private @NonNull List<SimulatedUser> getSavedUsers(final @NonNull HttpServletRequest request) {
    final String value = this.savedUsersCookie.getValue(request);
    return value != null ? SimulatedUser.parseList(value) : List.of();
  }

  /**
   * Gets the user and level of assurance that were selected the last time.
   *
   * @param request the HTTP servlet request
   * @return an array holding the personal identity number and the LoA URI, each of them may be {@code null}
   */
  private @Nullable String @NonNull [] getLastSelection(final @NonNull HttpServletRequest request) {
    final String value = this.selectedUserCookie.getValue(request);
    if (!StringUtils.hasText(value)) {
      return new String[2];
    }
    final String[] parts = value.split(SELECTION_SEPARATOR, 2);
    return new String[] { parts[0], parts.length > 1 ? parts[1] : null };
  }

  /**
   * Gets the name and logotype of the requester from the client registry.
   *
   * @param inputToken the input token
   * @param language the language of the page
   * @return the name and logotype, which are {@code null} if the requester is not found
   */
  private @NonNull RequesterDisplay getRequesterDisplay(final @NonNull UserAuthenticationInputToken inputToken,
      final @NonNull String language) {
    final ConfiguredAuthnServer server = this.configuredServer.getIfAvailable();
    final ClientRegistry registry = server != null ? server.getClientRegistry() : null;
    if (registry == null) {
      return new RequesterDisplay(null, null);
    }
    final Requester requester = inputToken.getRequester();
    try {
      final RequesterRecord record = registry.lookup(requester.protocol(), requester.identifier());
      return record != null ? RequesterDisplay.of(record, language) : new RequesterDisplay(null, null);
    }
    catch (final ClientRegistryException e) {
      log.warn("Failed to get the name and logotype of the requester: {} [{}]", e.getMessage(),
          inputToken.getLogString());
      return new RequesterDisplay(null, null);
    }
  }

  /**
   * Gets the personal identity number that the requester asks for, from a SAML {@code PrincipalSelection} or an OpenID
   * Connect claims request with a value. Both arrive as a requested attribute that carries the value.
   *
   * @param requirements the authentication requirements
   * @return the personal identity number, or {@code null} if none is requested
   */
  static @Nullable String getRequestedPersonalIdentityNumber(final @NonNull AuthenticationRequirements requirements) {
    return requirements.getRequestedAttributes().stream()
        .filter(a -> AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER.equals(a.getIdentifier()))
        .flatMap(a -> a.getRequestedValues().stream())
        .map(Serializable::toString)
        .filter(StringUtils::hasText)
        .findFirst()
        .orElse(null);
  }

  /**
   * Tells whether the requester is a signature service. A SAML Service Provider is one when its metadata declares the
   * signature service entity category, and an OpenID Connect client when it asks for the sign or the sign approval
   * scope. A request that carries a sign message always comes from a signature service, since the server only accepts
   * sign messages from those.
   *
   * @param requirements the authentication requirements
   * @return {@code true} for a signature service
   */
  static boolean isSignatureService(final @NonNull AuthenticationRequirements requirements) {
    if (requirements.getSignMessage() != null) {
      return true;
    }
    if (requirements instanceof final SamlAuthenticationRequirements saml) {
      return saml.getEntityCategories().contains(EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri());
    }
    if (requirements instanceof final OidcAuthenticationRequirements oidc) {
      return oidc.getScopes().contains(ScopeConstants.SIGN.getValue())
          || oidc.getScopes().contains(BuiltInScopes.SIGN_APPROVAL.getValue());
    }
    return false;
  }

  /**
   * Selects the message to show: the one for the language of the page, then one for the same primary language or
   * without a language, and otherwise the first one.
   *
   * @param message the message
   * @param language the language of the page
   * @return the message to show
   */
  static @NonNull LocalizedMessage selectMessage(final @NonNull GenericMessage message,
      final @NonNull String language) {
    final LocalizedMessage localized = message.getMessage(language);
    return localized != null ? localized : message.getMessages().getFirst();
  }

}

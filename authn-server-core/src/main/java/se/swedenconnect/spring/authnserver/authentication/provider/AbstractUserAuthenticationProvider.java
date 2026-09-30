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
package se.swedenconnect.spring.authnserver.authentication.provider;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.sso.SsoDecision;
import se.swedenconnect.spring.authnserver.sso.SsoDenialReason;
import se.swedenconnect.spring.authnserver.sso.SsoPolicy;
import se.swedenconnect.spring.authnserver.sso.SsoPolicyVoter;
import se.swedenconnect.spring.authnserver.sso.AuthnContextSsoVoter;
import se.swedenconnect.spring.authnserver.sso.RequestedAttributesSsoVoter;
import se.swedenconnect.spring.authnserver.sso.SsoVoter;

/**
 * Base class for a {@link UserAuthenticationProvider}. It handles everything around the authentication itself, so
 * that a module only has to implement {@link #authenticate(UserAuthenticationInputToken, List)}.
 * <p>
 * For every request, in this order:
 * </p>
 * <ol>
 * <li>The requested authentication contexts are filtered against the ones the provider supports. If none of them
 * remain, the provider does not handle the request and returns {@code null} so that another provider may take it.</li>
 * <li>Single sign-on is decided, see {@link #decideSso(UserAuthenticationInputToken, List)}. If a previous
 * authentication may be reused, it is returned and the use is recorded in its usage tracking.</li>
 * <li>If the request required that the user was not interacted with, and single sign-on was refused, the request fails
 * with {@link AuthenticationError#PASSIVE_NOT_POSSIBLE}, carrying the reason for the refusal.</li>
 * <li>Otherwise the user is authenticated.</li>
 * </ol>
 * <p>
 * The result, whether it comes from single sign-on or from a new authentication, is given the requirements and the
 * protocol data of the request, its use is recorded, and the {@link PostAuthenticationProcessor}s are run on it.
 * </p>
 * <p>
 * The single sign-on voters and the post-authentication processors are the provider's own, followed by those that the
 * server configuration assigns for the protocol of the requester, see
 * {@link #setServerSsoVoters(AuthenticationProtocol, List)} and
 * {@link #setServerPostAuthenticationProcessors(AuthenticationProtocol, List)}.
 * </p>
 *
 * @author Martin Lindström
 */
public abstract class AbstractUserAuthenticationProvider implements UserAuthenticationProvider {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(AbstractUserAuthenticationProvider.class);

  /** The voters that decide single sign-on, asked in order. */
  private final List<SsoVoter> ssoVoters;

  /** The provider's own processing that runs on a result. */
  private final List<PostAuthenticationProcessor> postAuthenticationProcessors;

  /** The single sign-on voters of the server configuration, per protocol, asked after the provider's own. */
  private final Map<AuthenticationProtocol, List<SsoVoter>> serverSsoVoters =
      new EnumMap<>(AuthenticationProtocol.class);

  /** The post-authentication processors of the server configuration, per protocol, run after the provider's own. */
  private final Map<AuthenticationProtocol, List<PostAuthenticationProcessor>> serverPostAuthenticationProcessors =
      new EnumMap<>(AuthenticationProtocol.class);

  /** The server default single sign-on policy. */
  private SsoPolicy serverSsoPolicy = SsoPolicy.defaultPolicy();

  /** The server single sign-on policies of the protocols that override the server default. */
  private final Map<AuthenticationProtocol, SsoPolicy> protocolSsoPolicies =
      new EnumMap<>(AuthenticationProtocol.class);

  /** The provider's own single sign-on policy, overriding the server default. */
  private SsoPolicy ssoPolicy;

  /**
   * Constructor installing the built-in single sign-on voters.
   */
  protected AbstractUserAuthenticationProvider() {
    this.ssoVoters = new ArrayList<>();
    this.ssoVoters.add(
        new SsoPolicyVoter((final AuthenticationProtocol protocol) -> this.getSsoPolicy(protocol)));
    this.ssoVoters.add(new AuthnContextSsoVoter());
    this.ssoVoters.add(new RequestedAttributesSsoVoter());
    this.postAuthenticationProcessors = new ArrayList<>();
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable Authentication authenticateUser(final @NonNull UserAuthenticationInputToken token)
      throws AuthenticationErrorException {

    final List<String> authnContextUris = this.filterRequestedAuthnContextUris(token);
    if (authnContextUris.isEmpty()) {
      log.info("None of the requested authentication contexts {} are supported by provider '{}' [{}]",
          token.getAuthnRequirements().getAuthnContextRequirements(), this.getName(), token.getLogString());
      return null;
    }

    final SsoDecision decision = this.decideSso(token, authnContextUris);
    if (decision.isAllowed()) {
      final UserAuthentication previous = Objects.requireNonNull(token.getPreviousAuthentication());
      log.debug("Reusing the authentication of '{}' for provider '{}' [{}]",
          previous.getName(), this.getName(), token.getLogString());
      this.completeResult(previous, token);
      return previous;
    }
    log.debug("Not reusing a previous authentication: {} [{}]", decision.reason(), token.getLogString());

    if (token.getAuthnRequirements().isPassiveAuthn()) {
      log.info("Passive authentication was requested, but no previous authentication could be reused: {} [{}]",
          decision.reason(), token.getLogString());
      throw new AuthenticationErrorException(AuthenticationError.PASSIVE_NOT_POSSIBLE,
          Objects.requireNonNull(decision.reason()));
    }

    final Authentication result = this.authenticate(token, authnContextUris);
    if (result instanceof final UserAuthentication userAuthentication) {
      this.completeResult(userAuthentication, token);
    }
    return result;
  }

  /**
   * Authenticates the user, once the checks around the authentication have been made.
   *
   * @param token what the provider is given
   * @param authnContextUris the authentication contexts that may be used, in the requester's order of preference
   * @return the authentication, normally a {@link UserAuthentication}
   * @throws AuthenticationErrorException if the authentication fails in a way that can be reported to the requester
   */
  protected abstract @NonNull Authentication authenticate(final @NonNull UserAuthenticationInputToken token,
      final @NonNull List<String> authnContextUris) throws AuthenticationErrorException;

  /**
   * Decides whether the previous authentication may be reused.
   * <p>
   * The rules that always apply are checked first, and no policy or voter can turn them off. After that the voters are
   * asked in order, the provider's own first and then those of the server configuration for the requester's protocol:
   * one denial ends it, and at least one {@link SsoDecision#allow()} is needed.
   * </p>
   *
   * @param token what the provider is given
   * @param authnContextUris the authentication contexts that may be used
   * @return an {@link SsoDecision}, which is either allowed or denied with a reason
   */
  protected @NonNull SsoDecision decideSso(final @NonNull UserAuthenticationInputToken token,
      final @NonNull List<String> authnContextUris) {

    final UserAuthentication previous = token.getPreviousAuthentication();
    if (previous == null) {
      return SsoDecision.deny(SsoDenialReason.NO_PREVIOUS_AUTHENTICATION);
    }
    final AuthenticationRequirements requirements = token.getAuthnRequirements();
    if (requirements.isForceAuthn()) {
      return SsoDecision.deny(SsoDenialReason.FORCE_AUTHN);
    }
    if (requirements.getMaxAuthnAge() != null && previous.getAuthenticatedUser().getAuthnInstant()
        .plus(requirements.getMaxAuthnAge()).isBefore(Instant.now())) {
      return SsoDecision.deny(SsoDenialReason.MAX_AUTHN_AGE_EXCEEDED);
    }
    if (!previous.isReuseForSso()) {
      return SsoDecision.deny(SsoDenialReason.NOT_REUSABLE);
    }
    if (requirements.getSignMessage() != null) {
      return SsoDecision.deny(SsoDenialReason.SIGN_MESSAGE);
    }
    if (!this.requestedAttributeValuesMatch(requirements, previous.getAuthenticatedUser())) {
      return SsoDecision.deny(SsoDenialReason.ATTRIBUTE_VALUE_MISMATCH);
    }

    boolean allowed = false;
    final List<SsoVoter> voters = new ArrayList<>(this.ssoVoters);
    voters.addAll(this.serverSsoVoters.getOrDefault(token.getRequester().protocol(), List.of()));
    for (final SsoVoter voter : voters) {
      final SsoDecision vote = voter.vote(previous, requirements, token.getRequester(), authnContextUris);
      if (vote.isDenied()) {
        return vote;
      }
      if (vote.isAllowed()) {
        allowed = true;
      }
    }
    return allowed ? SsoDecision.allow() : SsoDecision.deny(SsoDenialReason.NOT_ALLOWED);
  }

  /**
   * Given the requested authentication contexts, returns the ones that the provider supports, keeping the requester's
   * order of preference. When nothing was requested, every supported context applies.
   *
   * @param token what the provider is given
   * @return the authentication contexts that may be used, possibly empty
   */
  protected @NonNull List<String> filterRequestedAuthnContextUris(final @NonNull UserAuthenticationInputToken token) {
    final List<String> supported = this.getSupportedAuthnContextUris();
    final List<String> requested = token.getAuthnRequirements().getAuthnContextRequirements();
    if (requested.isEmpty()) {
      return supported;
    }
    return requested.stream()
        .filter(supported::contains)
        .toList();
  }

  /**
   * Gets the provider's own voters that decide single sign-on. The list is modifiable, so that an application can add
   * voters of its own or remove a built-in one. They are asked before the voters of the server configuration.
   *
   * @return the voters, in the order they are asked
   */
  public @NonNull List<SsoVoter> getSsoVoters() {
    return this.ssoVoters;
  }

  /**
   * Gets the provider's own processing that runs on a result. The list is modifiable and empty by default. The
   * processors run before those of the server configuration.
   *
   * @return the processors, in the order they are run
   */
  public @NonNull List<PostAuthenticationProcessor> getPostAuthenticationProcessors() {
    return this.postAuthenticationProcessors;
  }

  /**
   * Gets the single sign-on policy that applies to this provider, which is the provider's own policy if it has one and
   * the server default otherwise.
   *
   * @return the single sign-on policy
   */
  public @NonNull SsoPolicy getSsoPolicy() {
    return this.ssoPolicy != null ? this.ssoPolicy : this.serverSsoPolicy;
  }

  /**
   * Gets the single sign-on policy that applies to this provider for a request made with the given protocol. The order
   * is: the provider's own policy, the server policy of the protocol, and the server default.
   *
   * @param protocol the protocol of the requester
   * @return the single sign-on policy
   */
  public @NonNull SsoPolicy getSsoPolicy(final @NonNull AuthenticationProtocol protocol) {
    if (this.ssoPolicy != null) {
      return this.ssoPolicy;
    }
    return Objects.requireNonNullElse(this.protocolSsoPolicies.get(protocol), this.serverSsoPolicy);
  }

  /**
   * Assigns a single sign-on policy for this provider only. It takes precedence over the server default.
   *
   * @param ssoPolicy the policy, or {@code null} to follow the server default
   */
  public void setSsoPolicy(final @Nullable SsoPolicy ssoPolicy) {
    this.ssoPolicy = ssoPolicy;
  }

  /**
   * Assigns the server default single sign-on policy, which applies unless the provider has a policy of its own.
   *
   * @param serverSsoPolicy the server default policy
   */
  public void setServerSsoPolicy(final @NonNull SsoPolicy serverSsoPolicy) {
    this.serverSsoPolicy = Objects.requireNonNull(serverSsoPolicy, "serverSsoPolicy must not be null");
  }

  /**
   * Assigns the server single sign-on policy for one protocol. It takes precedence over the server default for
   * requests made with that protocol, but not over the provider's own policy.
   *
   * @param protocol the protocol
   * @param ssoPolicy the policy, or {@code null} to follow the server default for this protocol
   */
  public void setServerSsoPolicy(final @NonNull AuthenticationProtocol protocol, final @Nullable SsoPolicy ssoPolicy) {
    Objects.requireNonNull(protocol, "protocol must not be null");
    if (ssoPolicy != null) {
      this.protocolSsoPolicies.put(protocol, ssoPolicy);
    }
    else {
      this.protocolSsoPolicies.remove(protocol);
    }
  }

  /**
   * Assigns the single sign-on voters of the server configuration for one protocol. They are asked after the provider's
   * own voters, for requests made with that protocol.
   *
   * @param protocol the protocol
   * @param voters the voters, or {@code null} for none
   */
  public void setServerSsoVoters(final @NonNull AuthenticationProtocol protocol,
      final @Nullable List<SsoVoter> voters) {
    Objects.requireNonNull(protocol, "protocol must not be null");
    this.serverSsoVoters.put(protocol, voters != null ? List.copyOf(voters) : List.of());
  }

  /**
   * Assigns the post-authentication processors of the server configuration for one protocol. They run after the
   * provider's own processors, for requests made with that protocol.
   *
   * @param protocol the protocol
   * @param processors the processors, or {@code null} for none
   */
  public void setServerPostAuthenticationProcessors(final @NonNull AuthenticationProtocol protocol,
      final @Nullable List<PostAuthenticationProcessor> processors) {
    Objects.requireNonNull(protocol, "protocol must not be null");
    this.serverPostAuthenticationProcessors.put(protocol, processors != null ? List.copyOf(processors) : List.of());
  }

  /**
   * Gives the result what the rest of the server needs, records its use, and runs the post-authentication processing.
   *
   * @param authentication the result
   * @param token what the provider was given
   * @throws AuthenticationErrorException if the post-authentication processing rejects the result
   */
  protected void completeResult(final @NonNull UserAuthentication authentication,
      final @NonNull UserAuthenticationInputToken token) throws AuthenticationErrorException {
    authentication.setAuthnRequirements(token.getAuthnRequirements());
    authentication.setProtocolRequestData(token.getProtocolRequestData());
    authentication.registerUse(token.getRequester().protocol(), token.getRequester().identifier(),
        token.getRequestId(), token.getAuthnRequirements().getRequestedAttributes().stream()
            .map(GenericRequestedAttribute::getIdentifier)
            .toList());
    final List<PostAuthenticationProcessor> processors = new ArrayList<>(this.postAuthenticationProcessors);
    processors.addAll(
        this.serverPostAuthenticationProcessors.getOrDefault(token.getRequester().protocol(), List.of()));
    new DelegatingPostAuthenticationProcessor(processors).process(authentication);
  }

  /**
   * Checks that every attribute value the requester asked for matches what the user has. An attribute the user does not
   * have says nothing, so it is not a mismatch.
   *
   * @param requirements what the requester asks for
   * @param user the authenticated user
   * @return {@code true} if nothing contradicts the user and {@code false} otherwise
   */
  private boolean requestedAttributeValuesMatch(final @NonNull AuthenticationRequirements requirements,
      final @NonNull AuthenticatedUser user) {
    for (final GenericRequestedAttribute requested : requirements.getRequestedAttributes()) {
      if (requested.getRequestedValues().isEmpty()) {
        continue;
      }
      final GenericAttribute<?> attribute = user.getAttribute(requested.getIdentifier());
      if (attribute == null) {
        continue;
      }
      if (Collections.disjoint(attribute.getValues(), requested.getRequestedValues())) {
        return false;
      }
    }
    return true;
  }

}

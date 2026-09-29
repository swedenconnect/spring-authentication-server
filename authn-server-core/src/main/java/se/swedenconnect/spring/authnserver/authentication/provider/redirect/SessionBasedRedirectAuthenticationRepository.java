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
package se.swedenconnect.spring.authnserver.authentication.provider.redirect;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.util.WebUtils;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * The default storage, which keeps the authentications in the user's session.
 * <p>
 * The authentications are kept per identifier, so several of them may be in progress in the same session at once, for
 * example an OpenID Connect login in one browser tab and a SAML login in another. An authentication is removed when it
 * has been resumed, and one that is never resumed is removed once it is older than the maximum age, see
 * {@link #setMaxAge(Duration)}.
 * </p>
 *
 * @author Martin Lindström
 */
public class SessionBasedRedirectAuthenticationRepository implements RedirectAuthenticationRepository {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(SessionBasedRedirectAuthenticationRepository.class);

  /** The name of the session attribute where the authentications in progress are kept. */
  public static final String SESSION_KEY =
      SessionBasedRedirectAuthenticationRepository.class.getPackageName() + ".RedirectAuthentications";

  /** The maximum age of an authentication that has not been resumed, 30 minutes. */
  public static final Duration DEFAULT_MAX_AGE = Duration.ofMinutes(30);

  /** The maximum age of an authentication that has not been resumed. */
  private Duration maxAge = DEFAULT_MAX_AGE;

  /**
   * Assigns the maximum age of an authentication that has not been resumed. An older authentication is removed, and
   * resuming it gives {@link CommonUnrecoverableError#INVALID_SESSION}. Defaults to
   * {@link #DEFAULT_MAX_AGE 30 minutes}.
   *
   * @param maxAge the maximum age
   */
  public void setMaxAge(final @Nonnull Duration maxAge) {
    Objects.requireNonNull(maxAge, "maxAge must not be null");
    if (maxAge.isNegative() || maxAge.isZero()) {
      throw new IllegalArgumentException("maxAge must be positive");
    }
    this.maxAge = maxAge;
  }

  /**
   * Gets the maximum age of an authentication that has not been resumed.
   *
   * @return the maximum age
   */
  public @Nonnull Duration getMaxAge() {
    return this.maxAge;
  }

  /** {@inheritDoc} */
  @Override
  public void start(final @Nonnull RedirectForAuthenticationToken token,
      final @Nonnull HttpServletRequest request) {
    Objects.requireNonNull(token, "token must not be null");
    final HttpSession session = Objects.requireNonNull(request, "request must not be null").getSession();
    synchronized (WebUtils.getSessionMutex(session)) {
      final Map<String, RedirectAuthenticationState> states = this.states(session);
      this.removeExpired(states);
      states.put(token.getAuthnId(), new RedirectAuthenticationState(token, Instant.now()));
      session.setAttribute(SESSION_KEY, (Serializable) states);
    }
    log.debug("Started redirect authentication '{}' [{}]", token.getAuthnId(),
        token.getAuthnInputToken().getLogString());
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable AuthenticationProtocol getProtocol(final @Nonnull HttpServletRequest request) {
    final RedirectAuthenticationState state = this.find(request);
    return state != null ? state.getProtocol() : null;
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull ResumedAuthenticationToken resume(final @Nonnull HttpServletRequest request)
      throws UnrecoverableErrorException {

    final String authnId = RedirectForAuthenticationToken.getAuthnId(request);
    if (authnId == null) {
      throw invalidSession("No identifier of the authentication in the request");
    }
    final HttpSession session = request.getSession(false);
    final RedirectAuthenticationState state;
    if (session == null) {
      state = null;
    }
    else {
      synchronized (WebUtils.getSessionMutex(session)) {
        final Map<String, RedirectAuthenticationState> states = this.states(session);
        final RedirectAuthenticationState stored = states.get(authnId);
        state = stored != null && !stored.isExpired(this.maxAge) ? stored : null;
        if (stored != null) {
          states.remove(authnId);
          this.removeExpired(states);
          session.setAttribute(SESSION_KEY, (Serializable) states);
        }
      }
    }
    if (state == null) {
      throw invalidSession("No authentication '%s' in progress".formatted(authnId));
    }
    if (!state.isCompleted()) {
      throw invalidSession("The authentication '%s' has not been completed".formatted(authnId));
    }
    final ResumedAuthenticationToken token = state.toResumedToken();
    token.setServletRequest(request);
    log.debug("Resuming redirect authentication '{}' [{}]", authnId, token.getAuthnInputToken().getLogString());
    return token;
  }

  /** {@inheritDoc} */
  @Override
  public void clear(final @Nonnull HttpServletRequest request) {
    final String authnId = RedirectForAuthenticationToken.getAuthnId(request);
    final HttpSession session = Objects.requireNonNull(request, "request must not be null").getSession(false);
    if (authnId == null || session == null) {
      return;
    }
    synchronized (WebUtils.getSessionMutex(session)) {
      final Map<String, RedirectAuthenticationState> states = this.states(session);
      states.remove(authnId);
      this.removeExpired(states);
      session.setAttribute(SESSION_KEY, (Serializable) states);
    }
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable RedirectForAuthenticationToken getInputToken(final @Nonnull HttpServletRequest request) {
    final RedirectAuthenticationState state = this.find(request);
    return state != null ? state.getRedirectToken() : null;
  }

  /** {@inheritDoc} */
  @Override
  public void complete(final @Nonnull Authentication result, final @Nonnull HttpServletRequest request)
      throws IllegalStateException {
    Objects.requireNonNull(result, "result must not be null");
    this.complete(request, state -> state.complete(result));
  }

  /** {@inheritDoc} */
  @Override
  public void complete(final @Nonnull AuthenticationErrorException error, final @Nonnull HttpServletRequest request)
      throws IllegalStateException {
    Objects.requireNonNull(error, "error must not be null");
    this.complete(request, state -> state.complete(error));
  }

  /**
   * Records an outcome on the authentication that the request concerns and writes it back to the session.
   *
   * @param request the HTTP servlet request
   * @param outcome what to record on the state
   * @throws IllegalStateException if there is no such authentication
   */
  private void complete(final @Nonnull HttpServletRequest request,
      final @Nonnull Consumer<RedirectAuthenticationState> outcome) {
    final String authnId = RedirectForAuthenticationToken.getAuthnId(request);
    final HttpSession session = Objects.requireNonNull(request, "request must not be null").getSession(false);
    if (authnId == null || session == null) {
      throw new IllegalStateException("No authentication in progress for the request");
    }
    synchronized (WebUtils.getSessionMutex(session)) {
      final Map<String, RedirectAuthenticationState> states = this.states(session);
      final RedirectAuthenticationState state = states.get(authnId);
      if (state == null || state.isExpired(this.maxAge)) {
        throw new IllegalStateException("No authentication '%s' in progress".formatted(authnId));
      }
      outcome.accept(state);
      session.setAttribute(SESSION_KEY, (Serializable) states);
    }
  }

  /**
   * Finds the authentication that a request concerns, provided that it exists and has not expired.
   *
   * @param request the HTTP servlet request
   * @return the state, or {@code null} if there is none
   */
  private @Nullable RedirectAuthenticationState find(final @Nonnull HttpServletRequest request) {
    final String authnId = RedirectForAuthenticationToken.getAuthnId(request);
    final HttpSession session = Objects.requireNonNull(request, "request must not be null").getSession(false);
    if (authnId == null || session == null) {
      return null;
    }
    synchronized (WebUtils.getSessionMutex(session)) {
      final RedirectAuthenticationState state = this.states(session).get(authnId);
      return state != null && !state.isExpired(this.maxAge) ? state : null;
    }
  }

  /**
   * Gets the authentications in progress from the session. The map is the one stored in the session, or a new one when
   * the session holds nothing.
   *
   * @param session the session
   * @return the authentications in progress, keyed by identifier
   */
  @SuppressWarnings("unchecked")
  private @Nonnull Map<String, RedirectAuthenticationState> states(final @Nonnull HttpSession session) {
    final Object attribute = session.getAttribute(SESSION_KEY);
    if (attribute instanceof final Map<?, ?> map) {
      return (Map<String, RedirectAuthenticationState>) map;
    }
    return new LinkedHashMap<>();
  }

  /**
   * Removes the authentications that were started longer ago than the maximum age.
   *
   * @param states the authentications in progress
   */
  private void removeExpired(final @Nonnull Map<String, RedirectAuthenticationState> states) {
    states.entrySet().removeIf(entry -> {
      if (entry.getValue().isExpired(this.maxAge)) {
        log.debug("Removing expired redirect authentication '{}'", entry.getKey());
        return true;
      }
      return false;
    });
  }

  /**
   * Creates the "invalid session" error.
   *
   * @param message a message for logs
   * @return an {@link UnrecoverableErrorException}
   */
  private static @Nonnull UnrecoverableErrorException invalidSession(final @Nonnull String message) {
    log.info("Can not resume redirect authentication: {}", message);
    return new UnrecoverableErrorException(CommonUnrecoverableError.INVALID_SESSION, message);
  }

}

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
package se.swedenconnect.spring.authnserver.config;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.session.DisableEncodeUrlFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import se.swedenconnect.spring.authnserver.attributes.release.AttributeProducer;
import se.swedenconnect.spring.authnserver.audit.AuthnAuditFilter;
import se.swedenconnect.spring.authnserver.audit.AuthnEventPublisher;
import se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseVoter;
import se.swedenconnect.spring.authnserver.attributes.release.DefaultAttributeProducer;
import se.swedenconnect.spring.authnserver.attributes.release.IncludeAllAttributeReleaseVoter;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.provider.AbstractUserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.PostAuthenticationProcessor;
import se.swedenconnect.spring.authnserver.authentication.provider.SwedenConnectPostAuthenticationProcessor;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.SessionBasedRedirectAuthenticationRepository;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.UserRedirectAuthenticationProvider;
import se.swedenconnect.spring.authnserver.entity.EntityInformation;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.DefaultClientRegistry;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.acceptance.ConfigurableRequesterAcceptance;
import se.swedenconnect.spring.authnserver.registry.acceptance.RequesterAcceptance;
import se.swedenconnect.spring.authnserver.registry.changes.ClientChangeTracker;
import se.swedenconnect.spring.authnserver.sso.SsoPolicy;
import se.swedenconnect.spring.authnserver.sso.SsoVoter;
import se.swedenconnect.spring.authnserver.subject.AbstractSubjectIdentifierGenerator;
import se.swedenconnect.spring.authnserver.web.ResumedAuthenticationHandler;
import se.swedenconnect.spring.authnserver.web.UserAuthenticationFlow;
import se.swedenconnect.spring.authnserver.web.UserAuthenticationResumeFilter;

/**
 * The configurer for the whole authentication server. It holds the values that are common to all protocols, and the
 * configurers of the protocols that the server offers, and applies them in one {@link SecurityFilterChain} that matches
 * the endpoints of those protocols.
 * <p>
 * Some of the shared values may be overridden by a protocol, see {@link AbstractProtocolConfigurer}. A protocol value,
 * when assigned, wins over the shared one.
 * </p>
 * <p>
 * The attribute producers, the attribute release voters, the single sign-on voters and the post-authentication
 * processors are each a shared list here plus a list on each protocol configurer. For a request, the entries of the
 * protocol come first, followed by the shared ones. An entry that applies to all protocols belongs in the shared list.
 * </p>
 * <p>
 * The chain also serves the authentication paths and the resume paths of the redirect providers. The resume paths are
 * handled once for the whole server, and the flow continues in the protocol that the authentication was started for.
 * </p>
 * <p>
 * The first filter of the chain is an {@link AuthnAuditFilter}, which keeps the correlation ID of the audit events to
 * the request. The events are published to the {@link ApplicationContext}, see
 * {@link #eventPublisher(ApplicationEventPublisher)}.
 * </p>
 * <p>
 * Every value is checked when the filter chain is built. Without Spring Boot, set up the chain like this:
 * </p>
 *
 * <pre>{@code
 * final AuthnServerConfigurer configurer = new AuthnServerConfigurer()
 *     .baseUrl("https://idp.example.com")
 *     .authenticationProvider(provider)
 *     .protocol(new Saml2IdpConfigurer()
 *         .defaultCredential(credential));
 * AuthnServerConfigurer.applyDefaultSecurity(http, configurer);
 * return http.build();
 * }</pre>
 *
 * @author Martin Lindström
 */
public class AuthnServerConfigurer extends AbstractHttpConfigurer<AuthnServerConfigurer, HttpSecurity> {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(AuthnServerConfigurer.class);

  /** The default clock skew, 30 seconds. */
  public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(30);

  /** A client registry that knows no requesters, for a server without any backends. */
  private static final ClientRegistry EMPTY_CLIENT_REGISTRY = new ClientRegistry() {

    @Override
    public @Nullable RequesterRecord lookup(final @NonNull Requester requester) {
      return null;
    }

    @Override
    public @Nullable RequesterRecord requestMark(final @NonNull Requester requester, final @NonNull String mark) {
      return null;
    }
  };

  /** The base URL: protocol, host and context path. */
  private String baseUrl;

  /** The shared single sign-on policy. */
  private SsoPolicy ssoPolicy = SsoPolicy.defaultPolicy();

  /** The shared clock skew. */
  private Duration clockSkew = DEFAULT_CLOCK_SKEW;

  /** The shared descriptive information about the server and its organization. */
  private EntityInformation entityInformation = EntityInformation.empty();

  /** Whether user messages are supported. */
  private boolean supportsUserMessage = false;

  /** The shared subject identifier secret. */
  private byte[] subjectIdentifierSecret;

  /** The shared subject identifier hash algorithm. */
  private String subjectIdentifierHashAlgorithm = AbstractSubjectIdentifierGenerator.DEFAULT_HASH_ALGORITHM;

  /** The maximum age of an authentication in progress. */
  private Duration authnFlowMaxAge = SessionBasedRedirectAuthenticationRepository.DEFAULT_MAX_AGE;

  /** The authentication providers. */
  private final List<UserAuthenticationProvider> authenticationProviders = new ArrayList<>();

  /** The protocol configurers, keyed by their type. */
  private final Map<Class<?>, AbstractProtocolConfigurer<?>> protocols = new LinkedHashMap<>();

  /** The client registry, if assigned by the application. */
  private ClientRegistry clientRegistry;

  /** Client registry backends added by the application, on top of those of the protocol configurers. */
  private final List<ClientRegistryBackend> clientRegistryBackends = new ArrayList<>();

  /** The client registry that is used, assigned when the configurer is initialized. */
  private ClientRegistry activeClientRegistry;

  /** Is told when a client appears in or disappears from the registry, or {@code null}. */
  private ClientChangeTracker clientChangeTracker;

  /** The requester acceptance check. */
  private RequesterAcceptance requesterAcceptance;

  /** The shared attribute producers. */
  private final List<AttributeProducer> attributeProducers = new ArrayList<>(List.of(new DefaultAttributeProducer()));

  /** The shared attribute release voters. */
  private final List<AttributeReleaseVoter> attributeReleaseVoters =
      new ArrayList<>(List.of(new IncludeAllAttributeReleaseVoter()));

  /** The shared single sign-on voters. */
  private final List<SsoVoter> ssoVoters = new ArrayList<>();

  /** The shared post-authentication processors. */
  private final List<PostAuthenticationProcessor> postAuthenticationProcessors =
      new ArrayList<>(List.of(new SwedenConnectPostAuthenticationProcessor()));

  /** The matcher for the endpoints of all protocols, assigned when the configurer is initialized. */
  private RequestMatcher endpointsMatcher;

  /** The matcher for the authentication paths of the redirect providers, assigned when initialized. */
  private RequestMatcher authnPathsMatcher;

  /** The user authentication flow, assigned when the configurer is initialized. */
  private UserAuthenticationFlow userAuthenticationFlow;

  /** The application event publisher, if assigned by the application. */
  private ApplicationEventPublisher eventPublisher;

  /** The publisher of the events of the authentication flows, assigned when the configurer is initialized. */
  private AuthnEventPublisher activeEventPublisher;

  /**
   * Applies the configurer to the supplied {@link HttpSecurity} object, and makes the filter chain match the endpoints
   * of the configured protocols.
   * <p>
   * The caller may adjust the configurer after this call, since the values are read when the chain is built.
   * </p>
   *
   * @param http the HTTP security object
   * @param configurer the configurer
   * @throws Exception for configuration errors
   */
  public static void applyDefaultSecurity(final @NonNull HttpSecurity http,
      final @NonNull AuthnServerConfigurer configurer) throws Exception {

    final RequestMatcher endpointsMatcher = configurer.getEndpointsMatcher();
    http
        .securityMatcher(endpointsMatcher)
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers(configurer.getAuthnPathsMatcher()).permitAll()
            .anyRequest().authenticated())
        .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
        .securityContext(securityContext -> securityContext.requireExplicitSave(false))
        .with(configurer, Customizer.withDefaults());
  }

  /**
   * Assigns the base URL, that is, the protocol, host and context path of the server, for example
   * {@code https://idp.example.com/auth}. It must not end with a {@code /}. Required.
   *
   * @param baseUrl the base URL
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer baseUrl(final @NonNull String baseUrl) {
    this.baseUrl = baseUrl;
    return this;
  }

  /**
   * Gets the base URL.
   *
   * @return the base URL, or {@code null} if it has not been assigned
   */
  public @Nullable String getBaseUrl() {
    return this.baseUrl;
  }

  /**
   * Assigns the shared single sign-on policy. It applies unless a protocol or an authentication provider has a policy
   * of its own. The order is: provider, protocol, shared.
   *
   * @param ssoPolicy the policy
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer ssoPolicy(final @NonNull SsoPolicy ssoPolicy) {
    this.ssoPolicy = Objects.requireNonNull(ssoPolicy, "ssoPolicy must not be null");
    return this;
  }

  /**
   * Gets the shared single sign-on policy. Defaults to {@link SsoPolicy#defaultPolicy()}.
   *
   * @return the policy
   */
  public @NonNull SsoPolicy getSsoPolicy() {
    return this.ssoPolicy;
  }

  /**
   * Assigns the shared descriptive information about the server and its organization, published by every protocol. A
   * protocol may override any part of it, see {@link EntityInformation#overriddenBy(EntityInformation)}.
   *
   * @param entityInformation the information, or {@code null} for none
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer entityInformation(final @Nullable EntityInformation entityInformation) {
    this.entityInformation = entityInformation != null ? entityInformation : EntityInformation.empty();
    return this;
  }

  /**
   * Gets the shared descriptive information about the server and its organization.
   *
   * @return the information, which may be empty
   */
  public @NonNull EntityInformation getEntityInformation() {
    return this.entityInformation;
  }

  /**
   * Assigns the shared clock skew, the time that clocks of other parties may differ from the server clock.
   *
   * @param clockSkew the clock skew
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer clockSkew(final @NonNull Duration clockSkew) {
    this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew must not be null");
    return this;
  }

  /**
   * Gets the shared clock skew. Defaults to {@link #DEFAULT_CLOCK_SKEW}.
   *
   * @return the clock skew
   */
  public @NonNull Duration getClockSkew() {
    return this.clockSkew;
  }

  /**
   * Assigns whether the server supports displaying a user message from the requester.
   *
   * @param supportsUserMessage whether user messages are supported
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer supportsUserMessage(final boolean supportsUserMessage) {
    this.supportsUserMessage = supportsUserMessage;
    return this;
  }

  /**
   * Tells whether the server supports user messages. Defaults to {@code false}.
   *
   * @return {@code true} if user messages are supported and {@code false} otherwise
   */
  public boolean isSupportsUserMessage() {
    return this.supportsUserMessage;
  }

  /**
   * Assigns the shared secret used when subject identifiers are computed. Assigning a secret is strongly recommended.
   *
   * @param secret the secret, or {@code null} for no secret
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer subjectIdentifierSecret(final byte @Nullable [] secret) {
    this.subjectIdentifierSecret = secret != null ? secret.clone() : null;
    return this;
  }

  /**
   * Gets the shared subject identifier secret.
   *
   * @return the secret, or {@code null} if none has been assigned
   */
  public byte @Nullable [] getSubjectIdentifierSecret() {
    return this.subjectIdentifierSecret != null ? this.subjectIdentifierSecret.clone() : null;
  }

  /**
   * Assigns the shared hash algorithm used when subject identifiers are computed.
   *
   * @param hashAlgorithm the JCE name of the hash algorithm
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer subjectIdentifierHashAlgorithm(final @NonNull String hashAlgorithm) {
    this.subjectIdentifierHashAlgorithm = Objects.requireNonNull(hashAlgorithm, "hashAlgorithm must not be null");
    return this;
  }

  /**
   * Gets the shared subject identifier hash algorithm. Defaults to
   * {@value AbstractSubjectIdentifierGenerator#DEFAULT_HASH_ALGORITHM}.
   *
   * @return the JCE name of the hash algorithm
   */
  public @NonNull String getSubjectIdentifierHashAlgorithm() {
    return this.subjectIdentifierHashAlgorithm;
  }

  /**
   * Assigns the maximum age of an authentication in progress, that is, how long the server waits for the user to come
   * back from an authentication module.
   *
   * @param authnFlowMaxAge the maximum age
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer authnFlowMaxAge(final @NonNull Duration authnFlowMaxAge) {
    this.authnFlowMaxAge = Objects.requireNonNull(authnFlowMaxAge, "authnFlowMaxAge must not be null");
    return this;
  }

  /**
   * Gets the maximum age of an authentication in progress. Defaults to
   * {@link SessionBasedRedirectAuthenticationRepository#DEFAULT_MAX_AGE}.
   *
   * @return the maximum age
   */
  public @NonNull Duration getAuthnFlowMaxAge() {
    return this.authnFlowMaxAge;
  }

  /**
   * Assigns the client registry. When not assigned, a {@link DefaultClientRegistry} is created from the backends of
   * the protocol configurers and those added with {@link #clientRegistryBackend(ClientRegistryBackend)}.
   *
   * @param clientRegistry the client registry, or {@code null} to create the default
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer clientRegistry(final @Nullable ClientRegistry clientRegistry) {
    this.clientRegistry = clientRegistry;
    return this;
  }

  /**
   * Adds a client registry backend. The backends added here are asked before those of the protocol configurers. Not
   * used if a client registry has been assigned with {@link #clientRegistry(ClientRegistry)}.
   *
   * @param backend the backend
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer clientRegistryBackend(final @NonNull ClientRegistryBackend backend) {
    this.clientRegistryBackends.add(Objects.requireNonNull(backend, "backend must not be null"));
    return this;
  }

  /**
   * Gets the client registry backends that have been added with {@link #clientRegistryBackend(ClientRegistryBackend)},
   * in the order they were added. The backends of the protocol configurers are not included.
   *
   * @return the added backends
   */
  public @NonNull List<ClientRegistryBackend> getClientRegistryBackends() {
    return List.copyOf(this.clientRegistryBackends);
  }

  /**
   * Tells whether a client registry has been assigned with {@link #clientRegistry(ClientRegistry)}, in which case the
   * added backends are not used.
   *
   * @return {@code true} if a client registry has been assigned and {@code false} otherwise
   */
  public boolean isClientRegistryAssigned() {
    return this.clientRegistry != null;
  }

  /**
   * Assigns the object that is told when a client appears in or disappears from the client registry. It is given to
   * every backend of the registry when the configurer is initialized. Without one, no changes are tracked.
   *
   * @param clientChangeTracker the tracker, or {@code null}
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer clientChangeTracker(final @Nullable ClientChangeTracker clientChangeTracker) {
    this.clientChangeTracker = clientChangeTracker;
    return this;
  }

  /**
   * Gets the client change tracker.
   *
   * @return the tracker, or {@code null} if none has been assigned
   */
  public @Nullable ClientChangeTracker getClientChangeTracker() {
    return this.clientChangeTracker;
  }

  /**
   * Gets the client registry that the server uses. Available once the configurer has been initialized.
   *
   * @return the client registry
   * @throws IllegalStateException if the configurer has not been initialized
   */
  public @NonNull ClientRegistry getClientRegistry() {
    if (this.activeClientRegistry == null) {
      throw new IllegalStateException("AuthnServerConfigurer has not been initialized");
    }
    return this.activeClientRegistry;
  }

  /**
   * Assigns the check that decides whether a requester may use the server. When not assigned, every requester is
   * accepted.
   *
   * @param requesterAcceptance the check, or {@code null} to accept every requester
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer requesterAcceptance(final @Nullable RequesterAcceptance requesterAcceptance) {
    this.requesterAcceptance = requesterAcceptance;
    return this;
  }

  /**
   * Gets the check that decides whether a requester may use the server.
   *
   * @return the requester acceptance check
   */
  public @NonNull RequesterAcceptance getRequesterAcceptance() {
    return this.requesterAcceptance != null ? this.requesterAcceptance : RequesterAcceptance.acceptAll();
  }

  /**
   * Gets the {@link ConfigurableRequesterAcceptance}, for adding predicates. If no check has been assigned, a
   * {@link ConfigurableRequesterAcceptance} is created and assigned.
   *
   * @return the configurable requester acceptance
   * @throws IllegalStateException if another kind of check has been assigned
   */
  public @NonNull ConfigurableRequesterAcceptance configurableRequesterAcceptance() {
    if (this.requesterAcceptance == null) {
      this.requesterAcceptance = new ConfigurableRequesterAcceptance();
    }
    if (this.requesterAcceptance instanceof final ConfigurableRequesterAcceptance configurable) {
      return configurable;
    }
    throw new IllegalStateException("The requester acceptance check is a "
        + this.requesterAcceptance.getClass().getSimpleName() + ", not a ConfigurableRequesterAcceptance");
  }

  /**
   * Adds an authentication provider.
   *
   * @param provider the provider
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer authenticationProvider(final @NonNull UserAuthenticationProvider provider) {
    this.authenticationProviders.add(Objects.requireNonNull(provider, "provider must not be null"));
    return this;
  }

  /**
   * Gets the authentication providers. The list may be modified.
   *
   * @return the authentication providers
   */
  public @NonNull List<UserAuthenticationProvider> getAuthenticationProviders() {
    return this.authenticationProviders;
  }

  /**
   * Customizes the shared attribute producers. They run after the producers of the protocol, and the first producer to
   * release an attribute wins. The default is a {@link DefaultAttributeProducer}.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer attributeProducers(
      final @NonNull Customizer<List<AttributeProducer>> customizer) {
    customizer.customize(this.attributeProducers);
    return this;
  }

  /**
   * Gets the shared attribute producers. The list may be modified.
   *
   * @return the attribute producers
   */
  public @NonNull List<AttributeProducer> getAttributeProducers() {
    return this.attributeProducers;
  }

  /**
   * Customizes the shared attribute release voters. They are asked after the voters of the protocol. The default is an
   * {@link IncludeAllAttributeReleaseVoter}.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer attributeReleaseVoters(
      final @NonNull Customizer<List<AttributeReleaseVoter>> customizer) {
    customizer.customize(this.attributeReleaseVoters);
    return this;
  }

  /**
   * Gets the shared attribute release voters. The list may be modified.
   *
   * @return the attribute release voters
   */
  public @NonNull List<AttributeReleaseVoter> getAttributeReleaseVoters() {
    return this.attributeReleaseVoters;
  }

  /**
   * Customizes the shared single sign-on voters. They are asked after the provider's own voters and the voters of the
   * protocol. The list is empty by default.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer ssoVoters(final @NonNull Customizer<List<SsoVoter>> customizer) {
    customizer.customize(this.ssoVoters);
    return this;
  }

  /**
   * Gets the shared single sign-on voters. The list may be modified.
   *
   * @return the single sign-on voters
   */
  public @NonNull List<SsoVoter> getSsoVoters() {
    return this.ssoVoters;
  }

  /**
   * Customizes the shared post-authentication processors. They run after the provider's own processors and the
   * processors of the protocol. The default is a {@link SwedenConnectPostAuthenticationProcessor}.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer postAuthenticationProcessors(
      final @NonNull Customizer<List<PostAuthenticationProcessor>> customizer) {
    customizer.customize(this.postAuthenticationProcessors);
    return this;
  }

  /**
   * Gets the shared post-authentication processors. The list may be modified.
   *
   * @return the post-authentication processors
   */
  public @NonNull List<PostAuthenticationProcessor> getPostAuthenticationProcessors() {
    return this.postAuthenticationProcessors;
  }

  /**
   * Registers the configurer of a protocol. A protocol is offered by the server only when its configurer has been
   * registered. A configurer of the same type replaces a previously registered one.
   *
   * @param configurer the protocol configurer
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer protocol(final @NonNull AbstractProtocolConfigurer<?> configurer) {
    Objects.requireNonNull(configurer, "configurer must not be null");
    configurer.register(this);
    this.protocols.put(configurer.getClass(), configurer);
    return this;
  }

  /**
   * Customizes the configurer of a protocol.
   *
   * @param type the type of the protocol configurer
   * @param customizer the customizer
   * @param <T> the type of the protocol configurer
   * @return this configurer
   * @throws IllegalStateException if no configurer of the given type has been registered
   */
  public <T extends AbstractProtocolConfigurer<T>> @NonNull AuthnServerConfigurer protocol(
      final @NonNull Class<T> type, final @NonNull Customizer<T> customizer) {
    final T configurer = this.getProtocolConfigurer(type);
    if (configurer == null) {
      throw new IllegalStateException("No protocol configurer of type %s has been registered"
          .formatted(type.getSimpleName()));
    }
    customizer.customize(configurer);
    return this;
  }

  /**
   * Gets the configurer of a protocol.
   *
   * @param type the type of the protocol configurer
   * @param <T> the type of the protocol configurer
   * @return the configurer, or {@code null} if no configurer of that type has been registered
   */
  public <T extends AbstractProtocolConfigurer<T>> @Nullable T getProtocolConfigurer(final @NonNull Class<T> type) {
    return this.protocols.values().stream()
        .filter(type::isInstance)
        .map(type::cast)
        .findFirst()
        .orElse(null);
  }

  /**
   * Gets all registered protocol configurers.
   *
   * @return the protocol configurers
   */
  public @NonNull List<AbstractProtocolConfigurer<?>> getProtocolConfigurers() {
    return Collections.unmodifiableList(new ArrayList<>(this.protocols.values()));
  }

  /**
   * Gets a {@link RequestMatcher} for the endpoints of all configured protocols. It may be obtained before the
   * configurer has been initialized, but it may only be used after that.
   *
   * @return a request matcher
   */
  public @NonNull RequestMatcher getEndpointsMatcher() {
    return request -> {
      if (this.endpointsMatcher == null) {
        throw new IllegalStateException("AuthnServerConfigurer has not been initialized");
      }
      return this.endpointsMatcher.matches(request);
    };
  }

  /**
   * Gets a {@link RequestMatcher} for the authentication paths of the redirect providers, which are open to everyone.
   * It may be obtained before the configurer has been initialized, but it may only be used after that.
   *
   * @return a request matcher
   */
  public @NonNull RequestMatcher getAuthnPathsMatcher() {
    return request -> {
      if (this.authnPathsMatcher == null) {
        throw new IllegalStateException("AuthnServerConfigurer has not been initialized");
      }
      return this.authnPathsMatcher.matches(request);
    };
  }

  /**
   * Assigns the publisher of the application events that the server publishes, and that are turned into audit events.
   * When not assigned, the {@link ApplicationContext} of the {@link HttpSecurity} object is used. Without either,
   * nothing is published.
   *
   * @param eventPublisher the application event publisher, or {@code null} to use the application context
   * @return this configurer
   */
  public @NonNull AuthnServerConfigurer eventPublisher(final @Nullable ApplicationEventPublisher eventPublisher) {
    this.eventPublisher = eventPublisher;
    return this;
  }

  /**
   * Gets the publisher of the events of the authentication flows. Available once the configurer has been initialized.
   *
   * @return the event publisher
   * @throws IllegalStateException if the configurer has not been initialized
   */
  public @NonNull AuthnEventPublisher getEventPublisher() {
    if (this.activeEventPublisher == null) {
      throw new IllegalStateException("AuthnServerConfigurer has not been initialized");
    }
    return this.activeEventPublisher;
  }

  /**
   * Gets the flow that hands processed requests to the authentication providers. Available once the configurer has
   * been initialized.
   *
   * @return the user authentication flow
   * @throws IllegalStateException if the configurer has not been initialized
   */
  public @NonNull UserAuthenticationFlow getUserAuthenticationFlow() {
    if (this.userAuthenticationFlow == null) {
      throw new IllegalStateException("AuthnServerConfigurer has not been initialized");
    }
    return this.userAuthenticationFlow;
  }

  /** {@inheritDoc} */
  @Override
  public void init(final @NonNull HttpSecurity http) {
    this.validate();
    this.activeEventPublisher = new AuthnEventPublisher(this.eventPublisher != null
        ? this.eventPublisher
        : http.getSharedObject(ApplicationContext.class));
    this.userAuthenticationFlow = new UserAuthenticationFlow(this.authenticationProviders);
    this.userAuthenticationFlow.setEventPublisher(this.activeEventPublisher);

    final List<RequestMatcher> matchers = new ArrayList<>();
    for (final AbstractProtocolConfigurer<?> protocol : this.protocols.values()) {
      protocol.doInit(http);
      matchers.add(protocol.getRequestMatcher());
    }
    final List<RequestMatcher> authnPathMatchers = new ArrayList<>();
    for (final UserRedirectAuthenticationProvider provider : this.userAuthenticationFlow.getRedirectProviders()) {
      authnPathMatchers.add(PathPatternRequestMatcher.pathPattern(provider.getAuthnPath()));
      matchers.add(PathPatternRequestMatcher.pathPattern(provider.getResumeAuthnPath()));
      if (provider.getFlowRepository() instanceof final SessionBasedRedirectAuthenticationRepository repository) {
        repository.setMaxAge(this.authnFlowMaxAge);
      }
    }
    matchers.addAll(authnPathMatchers);
    this.authnPathsMatcher = authnPathMatchers.isEmpty() ? request -> false : new OrRequestMatcher(authnPathMatchers);
    this.endpointsMatcher = matchers.isEmpty() ? request -> false : new OrRequestMatcher(matchers);
    this.activeClientRegistry = this.createClientRegistry();
    if (this.clientChangeTracker != null) {
      this.activeClientRegistry.getBackends().forEach(b -> b.setClientChangeTracker(this.clientChangeTracker));
    }

    for (final UserAuthenticationProvider provider : this.authenticationProviders) {
      if (provider instanceof final AbstractUserAuthenticationProvider p) {
        p.setServerSsoPolicy(this.ssoPolicy);
        for (final AbstractProtocolConfigurer<?> c : this.protocols.values()) {
          p.setServerSsoPolicy(c.getProtocol(), c.getProtocolSsoPolicy());
          p.setServerSsoVoters(c.getProtocol(), combine(c.getSsoVoters(), this.ssoVoters));
          p.setServerPostAuthenticationProcessors(c.getProtocol(),
              combine(c.getPostAuthenticationProcessors(), this.postAuthenticationProcessors));
        }
      }
    }
    if (this.protocols.isEmpty()) {
      log.info("No protocol has been configured - the authentication server does not serve any endpoints");
    }
  }

  /** {@inheritDoc} */
  @Override
  public void configure(final @NonNull HttpSecurity http) {
    http.addFilterBefore(this.postProcess(new AuthnAuditFilter(this.getEventPublisher(),
        this.getUserAuthenticationFlow().getRedirectProviders())), DisableEncodeUrlFilter.class);
    this.protocols.values().forEach(p -> p.configure(http));

    final List<ResumedAuthenticationHandler> handlers = this.protocols.values().stream()
        .map(AbstractProtocolConfigurer::getResumedAuthenticationHandler)
        .filter(Objects::nonNull)
        .toList();
    final List<UserRedirectAuthenticationProvider> redirectProviders =
        this.getUserAuthenticationFlow().getRedirectProviders();
    if (!redirectProviders.isEmpty()) {
      http.addFilterAfter(this.postProcess(new UserAuthenticationResumeFilter(redirectProviders, handlers)),
          ExceptionTranslationFilter.class);
    }
  }

  /**
   * Combines the entries of a protocol with the shared ones, the protocol's first.
   *
   * @param protocolEntries the entries of the protocol
   * @param sharedEntries the shared entries
   * @param <E> the type of the entries
   * @return a new list
   */
  static <E> @NonNull List<E> combine(final @NonNull List<E> protocolEntries, final @NonNull List<E> sharedEntries) {
    final List<E> combined = new ArrayList<>(protocolEntries);
    combined.addAll(sharedEntries);
    return combined;
  }

  /**
   * Creates the client registry, unless one has been assigned, and checks that every protocol that needs a backend
   * has one.
   *
   * @return the client registry
   */
  private @NonNull ClientRegistry createClientRegistry() {
    if (this.clientRegistry != null) {
      return this.clientRegistry;
    }
    final List<ClientRegistryBackend> backends = new ArrayList<>(this.clientRegistryBackends);
    this.protocols.values().forEach(p -> backends.addAll(p.getClientRegistryBackends()));

    for (final AbstractProtocolConfigurer<?> protocol : this.protocols.values()) {
      final AuthenticationProtocol type = protocol.getProtocol();
      if (protocol.requiresClientRegistryBackend() && backends.stream().noneMatch(b -> b.getProtocol() == type)) {
        throw new IllegalArgumentException("No client registry backend for %s requesters - %s"
            .formatted(type, protocol.getMissingClientRegistryBackendHint()));
      }
    }
    assertUniqueSourceNames(backends);
    return backends.isEmpty() ? EMPTY_CLIENT_REGISTRY : new DefaultClientRegistry(backends);
  }

  /**
   * Checks that no two client sources of the same protocol have the same name.
   *
   * @param backends the backends
   * @throws IllegalArgumentException if a name is used more than once
   */
  static void assertUniqueSourceNames(final @NonNull List<ClientRegistryBackend> backends) {
    final Set<String> names = new HashSet<>();
    for (final ClientRegistryBackend backend : backends) {
      for (final String name : backend.getSourceNames()) {
        if (!names.add(backend.getProtocol() + ":" + name)) {
          throw new IllegalArgumentException(("Two %s client sources are named '%s' - the source names must be "
              + "unique per protocol, since management and audit tell the sources apart by them")
              .formatted(backend.getProtocol(), name));
        }
      }
    }
  }

  /**
   * Post processes an object created by a protocol configurer.
   *
   * @param object the object
   * @param <O> the type of the object
   * @return the processed object
   */
  <O> @NonNull O postProcessObject(final @NonNull O object) {
    return this.postProcess(object);
  }

  /**
   * Checks that the shared values are set and valid.
   *
   * @throws IllegalArgumentException if a value is missing or invalid
   */
  private void validate() {
    if (this.baseUrl == null || this.baseUrl.isBlank()) {
      throw new IllegalArgumentException(
          "Missing base URL - assign it with AuthnServerConfigurer.baseUrl() or the authn-server.base-url property");
    }
    assertBaseUrl(this.baseUrl, "Base URL");
    assertClockSkew(this.clockSkew, "Clock skew");
    if (this.subjectIdentifierSecret != null && this.subjectIdentifierSecret.length == 0) {
      throw new IllegalArgumentException("Subject identifier secret must not be empty");
    }
    assertHashAlgorithm(this.subjectIdentifierHashAlgorithm, "Subject identifier hash algorithm");
    if (this.authnFlowMaxAge.isNegative() || this.authnFlowMaxAge.isZero()) {
      throw new IllegalArgumentException("Maximum age of an authentication in progress must be positive");
    }
  }

  /**
   * Checks that a base URL is an absolute HTTP or HTTPS URL that does not end with a {@code /}.
   *
   * @param url the URL to check
   * @param name the name of the value, used in the error message
   * @throws IllegalArgumentException if the URL is invalid
   */
  public static void assertBaseUrl(final @NonNull String url, final @NonNull String name) {
    if (url.endsWith("/")) {
      throw new IllegalArgumentException("%s '%s' must not end with /".formatted(name, url));
    }
    try {
      final URI uri = new URI(url);
      if (!("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme()))
          || uri.getHost() == null || uri.getQuery() != null || uri.getFragment() != null) {
        throw new IllegalArgumentException(
            "%s '%s' must be an HTTP or HTTPS URL without query or fragment".formatted(name, url));
      }
    }
    catch (final URISyntaxException e) {
      throw new IllegalArgumentException("%s '%s' is not a valid URL".formatted(name, url), e);
    }
  }

  /**
   * Checks that a clock skew is not negative.
   *
   * @param clockSkew the clock skew
   * @param name the name of the value, used in the error message
   * @throws IllegalArgumentException if the value is negative
   */
  static void assertClockSkew(final @NonNull Duration clockSkew, final @NonNull String name) {
    if (clockSkew.isNegative()) {
      throw new IllegalArgumentException(name + " must not be negative");
    }
  }

  /**
   * Checks that a hash algorithm is available.
   *
   * @param hashAlgorithm the JCE name of the hash algorithm
   * @param name the name of the value, used in the error message
   * @throws IllegalArgumentException if the algorithm is not available
   */
  static void assertHashAlgorithm(final @NonNull String hashAlgorithm, final @NonNull String name) {
    try {
      MessageDigest.getInstance(hashAlgorithm);
    }
    catch (final NoSuchAlgorithmException e) {
      throw new IllegalArgumentException("%s '%s' is not supported".formatted(name, hashAlgorithm), e);
    }
  }

}

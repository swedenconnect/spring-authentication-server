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
package se.swedenconnect.spring.authnserver.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.annotation.Nonnull;
import jakarta.servlet.Filter;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;

import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;
import se.swedenconnect.security.credential.spring.autoconfigure.ConvertersAutoConfiguration;
import se.swedenconnect.security.credential.spring.autoconfigure.SpringCredentialBundlesAutoConfiguration;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.provider.AbstractUserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.autoconfigure.saml.SamlAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.saml.SamlCredentialConfiguration;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurerAdapter;
import se.swedenconnect.spring.authnserver.saml.config.Saml2IdpConfigurer;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.acceptance.ConfigurableRequesterAcceptance;
import se.swedenconnect.spring.authnserver.registry.acceptance.RequesterAcceptance;
import se.swedenconnect.spring.authnserver.registry.acceptance.RequesterPredicate;
import se.swedenconnect.spring.authnserver.registry.acceptance.RequiredMarksRequesterPredicate;
import se.swedenconnect.spring.authnserver.registry.acceptance.WhitelistRequesterPredicate;
import se.swedenconnect.spring.authnserver.sso.SsoPolicy;

/**
 * Test cases for {@link AuthnServerAutoConfiguration} and {@link SamlAutoConfiguration}.
 *
 * @author Martin Lindström
 */
class AuthnServerAutoConfigurationTest {

  private static final String BASE_URL = "https://idp.example.com/auth";

  private static final String CREDENTIALS = "authn-server.saml.credentials.";

  private static final String SP_ONE = "https://sp-one.example.com";

  private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SpringCredentialBundlesAutoConfiguration.class,
          ConvertersAutoConfiguration.class, SamlAutoConfiguration.class, AuthnServerAutoConfiguration.class));

  private static final String[] SAML = {
      "authn-server.base-url=" + BASE_URL,
      "authn-server.saml.enabled=true",
      CREDENTIALS + "default-credential.jks.store.location=classpath:credentials/idp-credentials.p12",
      CREDENTIALS + "default-credential.jks.store.password=secret",
      CREDENTIALS + "default-credential.jks.store.type=PKCS12",
      CREDENTIALS + "default-credential.jks.key.alias=sign",
      CREDENTIALS + "default-credential.jks.key.key-password=secret",
      "authn-server.saml.metadata-providers[0].location=classpath:metadata/sp-metadata.xml"
  };

  /** A provider for checking the single sign-on policies. */
  static class TestProvider extends AbstractUserAuthenticationProvider {

    @Override
    public @Nonnull String getName() {
      return "test";
    }

    @Override
    public @Nonnull List<String> getSupportedAuthnContextUris() {
      return List.of("http://id.elegnamnden.se/loa/1.0/loa3");
    }

    @Override
    protected @Nonnull Authentication authenticate(final @Nonnull UserAuthenticationInputToken token,
        final @Nonnull List<String> authnContextUris) {
      throw new UnsupportedOperationException();
    }
  }

  /** Captures the configurer. */
  @Configuration
  static class CaptureConfiguration {

    static final AtomicReference<AuthnServerConfigurer> CONFIGURER = new AtomicReference<>();

    @Bean
    TestProvider testProvider() {
      return new TestProvider();
    }

    @Bean
    @Order(10)
    AuthnServerConfigurerAdapter captureAdapter() {
      return (http, configurer) -> CONFIGURER.set(configurer);
    }
  }

  /** Adds a predicate that rejects every SAML requester, through an adapter. */
  @Configuration
  static class PredicateConfiguration {

    @Bean
    AuthnServerConfigurerAdapter predicateAdapter() {
      return (http, configurer) -> configurer.configurableRequesterAcceptance().addPredicate(new RequesterPredicate() {

        @Override
        public @Nonnull AuthenticationProtocol getProtocol() {
          return AuthenticationProtocol.SAML;
        }

        @Override
        public boolean test(final @Nonnull RequesterRecord record, final @Nonnull ClientRegistry registry) {
          return false;
        }
      });
    }
  }

  /** Adapters that change the entity ID, in order. */
  @Configuration
  static class AdapterConfiguration {

    @Bean
    @Order(2)
    AuthnServerConfigurerAdapter secondAdapter() {
      return (http, configurer) -> configurer.protocol(Saml2IdpConfigurer.class,
          s -> s.entityId("https://second.example.com"));
    }

    @Bean
    @Order(1)
    AuthnServerConfigurerAdapter firstAdapter() {
      return (http, configurer) -> configurer.protocol(Saml2IdpConfigurer.class,
          s -> s.entityId("https://first.example.com").path("/adapted"));
    }
  }

  @Test
  void startupFailsWhenNoProtocolIsEnabled() {
    this.runner.withPropertyValues("authn-server.base-url=" + BASE_URL)
        .run(context -> assertThat(context).hasFailed()
            .getFailure().rootCause().hasMessageContaining("No protocol is enabled"));
  }

  @Test
  void startupFailsWhenAnEnabledProtocolIsNotOnTheClasspath() {
    this.runner.withPropertyValues(SAML)
        .withClassLoader(new FilteredClassLoader(Saml2IdpConfigurer.class))
        .run(context -> assertThat(context).hasFailed()
            .getFailure().rootCause().hasMessageContaining("the authn-server-saml module is not on the classpath"));

    this.runner.withPropertyValues("authn-server.base-url=" + BASE_URL, "authn-server.oidc.enabled=true")
        .withClassLoader(new FilteredClassLoader("se.swedenconnect.spring.authnserver.oidc"))
        .run(context -> assertThat(context).hasFailed()
            .getFailure().rootCause().hasMessageContaining("the authn-server-oidc module is not on the classpath"));
  }

  @Test
  void startupFailsWhenTheBaseUrlIsMissing() {
    this.runner.withPropertyValues("authn-server.saml.enabled=true")
        .run(context -> assertThat(context).hasFailed()
            .getFailure().rootCause().hasMessageContaining("Missing base URL"));
  }

  @Test
  void startupFailsWhenARequiredSamlValueIsMissing() {
    this.runner.withPropertyValues("authn-server.base-url=" + BASE_URL, "authn-server.saml.enabled=true")
        .run(context -> assertThat(context).hasFailed()
            .getFailure().rootCause().hasMessageContaining("Missing SAML signing credential"));

    final String[] withoutMetadata = java.util.Arrays.copyOf(SAML, SAML.length - 1);
    this.runner.withPropertyValues(withoutMetadata)
        .run(context -> assertThat(context).hasFailed()
            .getFailure().rootCause().hasMessageContaining("No client registry backend for SAML requesters"));
  }

  @Test
  void theSpMetadataSourcesAreWiredIntoTheClientRegistry() {
    this.runner.withPropertyValues(SAML)
        .withUserConfiguration(CaptureConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final AuthnServerConfigurer configurer = CaptureConfiguration.CONFIGURER.get();
          assertThat(configurer.getClientRegistry().lookup(AuthenticationProtocol.SAML, SP_ONE)).isNotNull();
          assertThat(configurer.getClientRegistry().lookup(AuthenticationProtocol.SAML, "https://unknown")).isNull();
        });
  }

  @Test
  void withoutAcceptancePropertiesEverySpIsAccepted() {
    this.runner.withPropertyValues(SAML)
        .withUserConfiguration(CaptureConfiguration.class)
        .run(context -> {
          final AuthnServerConfigurer configurer = CaptureConfiguration.CONFIGURER.get();
          assertThat(configurer.getRequesterAcceptance()).isSameAs(RequesterAcceptance.acceptAll());
        });
  }

  @Test
  void theAcceptancePropertiesGiveTheSamlPredicates() {
    this.runner.withPropertyValues(SAML)
        .withPropertyValues(
            "authn-server.saml.requester-acceptance.mode=ANY",
            "authn-server.saml.requester-acceptance.whitelist[0]=https://other.example.com",
            "authn-server.saml.requester-acceptance.required-marks[0][0]="
                + "http://id.elegnamnden.se/ec/1.0/eidas-naturalperson",
            "authn-server.saml.requester-acceptance.required-marks[0][1]=http://id.elegnamnden.se/ec/1.0/loa4-pnr")
        .withUserConfiguration(CaptureConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final AuthnServerConfigurer configurer = CaptureConfiguration.CONFIGURER.get();
          final ConfigurableRequesterAcceptance acceptance = configurer.configurableRequesterAcceptance();
          assertThat(acceptance.getMode(AuthenticationProtocol.SAML))
              .isEqualTo(ConfigurableRequesterAcceptance.Mode.ANY);
          assertThat(acceptance.getPredicates()).hasSize(2);
          assertThat(acceptance.getPredicates().get(0)).isInstanceOfSatisfying(WhitelistRequesterPredicate.class,
              p -> assertThat(p.getIdentifiers()).containsExactly("https://other.example.com"));
          assertThat(acceptance.getPredicates().get(1)).isInstanceOfSatisfying(RequiredMarksRequesterPredicate.class,
              p -> assertThat(p.getGroups()).hasSize(1));

          final RequesterRecord record =
              configurer.getClientRegistry().lookup(AuthenticationProtocol.SAML, SP_ONE);
          assertThat(acceptance.isAccepted(record, configurer.getClientRegistry())).isFalse();
        });
  }

  @Test
  void aCustomPredicateAddedThroughAnAdapterTakesEffect() {
    this.runner.withPropertyValues(SAML)
        .withUserConfiguration(CaptureConfiguration.class, PredicateConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final AuthnServerConfigurer configurer = CaptureConfiguration.CONFIGURER.get();
          final RequesterRecord record =
              configurer.getClientRegistry().lookup(AuthenticationProtocol.SAML, SP_ONE);
          assertThat(configurer.getRequesterAcceptance().isAccepted(record, configurer.getClientRegistry()))
              .isFalse();
        });
  }

  @Test
  void anUnsupportedReplayTypeFailsStartup() {
    this.runner.withPropertyValues(SAML)
        .withPropertyValues("authn-server.saml.replay.type=redis")
        .run(context -> assertThat(context).hasFailed()
            .getFailure().rootCause().hasMessageContaining("authn-server.saml.replay.type"));
  }

  @Test
  void theRequestProcessingPropertiesAreApplied() {
    this.runner.withPropertyValues(SAML)
        .withPropertyValues(
            "authn-server.saml.max-message-age=PT1M",
            "authn-server.saml.assertions.encrypt=false",
            "authn-server.saml.assertions.not-after=PT10M",
            "authn-server.saml.assertions.not-before=PT30S",
            "authn-server.saml.replay.expiration=PT10M",
            "authn-server.saml.replay.context=my-context",
            "authn-server.saml.authn-context.minimum-mappings.[http://id.elegnamnden.se/loa/1.0/loa3]"
                + "=http://id.elegnamnden.se/loa/1.0/loa3,http://id.elegnamnden.se/loa/1.0/loa4")
        .withUserConfiguration(CaptureConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final Saml2IdpConfigurer saml =
              CaptureConfiguration.CONFIGURER.get().getProtocolConfigurer(Saml2IdpConfigurer.class);
          assertThat(saml.getMaxMessageAge()).isEqualTo(Duration.ofMinutes(1));
          assertThat(saml.isEncryptAssertions()).isFalse();
          assertThat(saml.getAssertionNotOnOrAfter()).isEqualTo(Duration.ofMinutes(10));
          assertThat(saml.getAssertionNotBefore()).isEqualTo(Duration.ofSeconds(30));
        });
  }

  @Test
  void anOidcOnlyServerStarts() {
    this.runner.withPropertyValues("authn-server.base-url=" + BASE_URL, "authn-server.oidc.enabled=true")
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).doesNotHaveBean(SamlAutoConfiguration.class);
          assertThat(context).hasSingleBean(SecurityFilterChain.class);
        });
  }

  @Test
  void theMetadataIsServedUnderTheBaseUrlAndTheEntityIdDefaultsToIt() {
    this.runner.withPropertyValues(SAML)
        .withClassLoader(new FilteredClassLoader("se.swedenconnect.spring.authnserver.oidc"))
        .run(context -> {
          assertThat(context).hasNotFailed();
          final MockHttpServletResponse response = get(context, "/saml2/metadata");
          assertThat(response.getStatus()).isEqualTo(200);
          final EntityDescriptor ed = parse(response);
          assertThat(ed.getEntityID()).isEqualTo(BASE_URL);
          assertThat(ed.getSignature()).isNotNull();
          assertThat(ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getSingleSignOnServices())
              .extracting(SingleSignOnService::getLocation)
              .containsExactly(BASE_URL + "/saml2/redirect/authn", BASE_URL + "/saml2/post/authn");
        });
  }

  @Test
  void changingTheSamlPathMovesEveryEndpoint() {
    this.runner.withPropertyValues(SAML)
        .withPropertyValues("authn-server.saml.path=/idp", "authn-server.saml.endpoints.metadata=/md",
            "authn-server.saml.endpoints.post-authn=/post")
        .run(context -> {
          assertThat(get(context, "/saml2/metadata").getContentAsByteArray()).isEmpty();
          final MockHttpServletResponse response = get(context, "/idp/md");
          assertThat(response.getStatus()).isEqualTo(200);
          assertThat(parse(response).getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getSingleSignOnServices())
              .extracting(SingleSignOnService::getLocation)
              .containsExactly(BASE_URL + "/idp/redirect/authn", BASE_URL + "/idp/post");

          final SecurityFilterChain chain = context.getBean(SecurityFilterChain.class);
          assertThat(chain.matches(request("POST", "/idp/post"))).isTrue();
          assertThat(chain.matches(request("POST", "/saml2/post/authn"))).isFalse();
        });
  }

  @Test
  void theSamlPropertiesAreApplied() {
    this.runner.withPropertyValues(SAML)
        .withPropertyValues(
            "authn-server.saml.entity-id=https://saml.example.com",
            "authn-server.saml.requires-signed-requests=false",
            CREDENTIALS + "future-sign=classpath:credentials/future-sign.crt",
            "authn-server.saml.metadata.cache-duration=PT2H",
            "authn-server.saml.metadata.ui-info.display-names.en=Test IdP",
            "authn-server.saml.metadata.ui-info.logotypes[0].path=/logo.svg",
            "authn-server.saml.metadata.ui-info.logotypes[0].height=100",
            "authn-server.saml.metadata.ui-info.logotypes[0].width=100",
            "authn-server.saml.metadata.organization.names.en=Org",
            "authn-server.saml.metadata.organization.display-names.en=Org",
            "authn-server.saml.metadata.organization.urls.en=https://www.example.com",
            "authn-server.saml.metadata.contact-persons.technical.email-addresses[0]=tech@example.com",
            "authn-server.saml.metadata.signing-methods[0].algorithm=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "authn-server.saml.metadata.encryption-methods[0].algorithm=http://www.w3.org/2009/xmlenc11#rsa-oaep")
        .run(context -> {
          assertThat(context).hasNotFailed();
          final EntityDescriptor ed = parse(get(context, "/saml2/metadata"));
          assertThat(ed.getEntityID()).isEqualTo("https://saml.example.com");
          assertThat(ed.getCacheDuration()).isEqualTo(Duration.ofHours(2));
          assertThat(ed.getOrganization().getOrganizationNames().getFirst().getValue()).isEqualTo("Org");
          assertThat(ed.getContactPersons()).hasSize(1);

          final IDPSSODescriptor idp = ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
          assertThat(idp.getWantAuthnRequestsSigned()).isFalse();
          final UIInfo uiInfo = EntityDescriptorUtils.getMetadataExtension(idp.getExtensions(), UIInfo.class);
          assertThat(uiInfo.getDisplayNames().getFirst().getValue()).isEqualTo("Test IdP");
          assertThat(uiInfo.getLogos().getFirst().getURI()).isEqualTo(BASE_URL + "/logo.svg");

          assertThat(idp.getKeyDescriptors()).extracting(KeyDescriptor::getUse)
              .containsExactly(UsageType.SIGNING, UsageType.UNSPECIFIED);
          assertThat(idp.getKeyDescriptors().get(1).getEncryptionMethods()).hasSize(1);
        });
  }

  @Test
  void aCredentialBeanReplacesTheProperty() throws Exception {
    final PkiCredential metadataCredential;
    try (final InputStream is = new ClassPathResource("credentials/idp-credentials.p12").getInputStream()) {
      metadataCredential = new KeyStoreCredential(
          KeyStoreFactory.loadKeyStore(is, "secret".toCharArray(), "PKCS12", null), "metadata", "secret".toCharArray());
    }
    this.runner.withPropertyValues(SAML)
        .withBean(SamlCredentialConfiguration.METADATA_SIGN_CREDENTIAL, PkiCredential.class, () -> metadataCredential)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final EntityDescriptor ed = parse(get(context, "/saml2/metadata"));
          SignatureValidator.validate(ed.getSignature(), new BasicX509Credential(metadataCredential.getCertificate()));
        });
  }

  @Test
  void anAdapterChangesAValueSetFromProperties() {
    this.runner.withPropertyValues(SAML)
        .withPropertyValues("authn-server.saml.entity-id=https://properties.example.com")
        .withUserConfiguration(AdapterConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final EntityDescriptor ed = parse(get(context, "/adapted/metadata"));
          assertThat(ed.getEntityID()).isEqualTo("https://second.example.com");
        });
  }

  @Test
  void aProtocolValueWinsOverTheSharedValue() {
    this.runner.withPropertyValues(SAML)
        .withPropertyValues(
            "authn-server.clock-skew=PT10S",
            "authn-server.supports-user-message=true",
            "authn-server.subject-identifier.secret=shared",
            "authn-server.authn-flow-max-age=PT10M",
            "authn-server.sso.time-limit=PT20M",
            "authn-server.saml.clock-skew=PT5S",
            "authn-server.saml.subject-identifier.hash-algorithm=SHA-512",
            "authn-server.saml.sso.same-requester-required=false")
        .withUserConfiguration(CaptureConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          final AuthnServerConfigurer configurer = CaptureConfiguration.CONFIGURER.get();
          final Saml2IdpConfigurer saml = configurer.getProtocolConfigurer(Saml2IdpConfigurer.class);

          assertThat(configurer.getAuthnFlowMaxAge()).isEqualTo(Duration.ofMinutes(10));
          assertThat(saml.getClockSkew()).isEqualTo(Duration.ofSeconds(5));
          assertThat(configurer.getClockSkew()).isEqualTo(Duration.ofSeconds(10));
          assertThat(saml.isSupportsUserMessage()).isTrue();
          assertThat(new String(saml.getSubjectIdentifierSecret())).isEqualTo("shared");
          assertThat(saml.getSubjectIdentifierHashAlgorithm()).isEqualTo("SHA-512");
          assertThat(configurer.getSubjectIdentifierHashAlgorithm()).isEqualTo("SHA-256");

          // The SAML policy takes the values it does not assign from the shared policy.
          assertThat(saml.getSsoPolicy().getTimeLimit()).isEqualTo(Duration.ofMinutes(20));
          assertThat(saml.getSsoPolicy().isSameRequesterRequired()).isFalse();

          final TestProvider provider = context.getBean(TestProvider.class);
          final SsoPolicy samlPolicy = provider.getSsoPolicy(AuthenticationProtocol.SAML);
          assertThat(samlPolicy.isSameRequesterRequired()).isFalse();
          final SsoPolicy oidcPolicy = provider.getSsoPolicy(AuthenticationProtocol.OIDC);
          assertThat(oidcPolicy.isSameRequesterRequired()).isTrue();
          assertThat(oidcPolicy.getTimeLimit()).isEqualTo(Duration.ofMinutes(20));

          // A provider's own policy wins over both.
          provider.setSsoPolicy(SsoPolicy.none());
          assertThat(provider.getSsoPolicy(AuthenticationProtocol.SAML).isEnabled()).isFalse();
        });
  }

  @Test
  void aTimeLimitThatIsNotPositiveFailsStartup() {
    this.runner.withPropertyValues(SAML)
        .withPropertyValues("authn-server.saml.sso.time-limit=0s")
        .run(context -> assertThat(context).hasFailed()
            .getFailure().rootCause().hasMessageContaining("authn-server.saml.sso.time-limit must be positive"));
  }

  @Test
  void singleSignOnIsTurnedOffWithTheEnabledSetting() {
    this.runner.withPropertyValues(SAML)
        .withPropertyValues("authn-server.sso.enabled=false")
        .withUserConfiguration(CaptureConfiguration.class)
        .run(context -> assertThat(CaptureConfiguration.CONFIGURER.get().getSsoPolicy().isEnabled()).isFalse());
  }

  private static MockHttpServletResponse get(final AssertableWebApplicationContext context, final String path)
      throws Exception {
    final Filter filter = context.getBean("springSecurityFilterChain", Filter.class);
    final MockHttpServletResponse response = new MockHttpServletResponse();
    filter.doFilter(request("GET", path), response, new MockFilterChain());
    return response;
  }

  private static MockHttpServletRequest request(final String method, final String path) {
    final MockHttpServletRequest request = new MockHttpServletRequest(method, path);
    request.setServletPath(path);
    return request;
  }

  private static EntityDescriptor parse(final MockHttpServletResponse response) throws Exception {
    return (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(
        XMLObjectProviderRegistrySupport.getParserPool(), new ByteArrayInputStream(response.getContentAsByteArray()));
  }

}

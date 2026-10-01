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
package se.swedenconnect.spring.authnserver.autoconfigure.storage;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import se.swedenconnect.spring.authnserver.oidc.token.AccessTokenData;
import se.swedenconnect.spring.authnserver.oidc.token.AccessTokenStore;
import se.swedenconnect.spring.authnserver.oidc.token.RedisAccessTokenStore;

/**
 * Tests for the TLS host name check and the Redis Cluster NAT translation of {@link RedisClientConfiguration}, against
 * Redis containers. The TLS container has a server certificate for another host name than the one the tests connect
 * to.
 *
 * @author Martin Lindström
 */
@Testcontainers(disabledWithoutDocker = true)
class RedisClientConfigurationTest {

  /** The host name in the server certificate, which is not the one the tests connect to. */
  private static final String SERVER_NAME = "redis.example.com";

  private static final Certificates TRUSTED = new Certificates("Trusted CA");

  private static final Certificates UNTRUSTED = new Certificates("Untrusted CA");

  @Container
  private static final GenericContainer<?> TLS_REDIS =
      new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
          .withExposedPorts(6379)
          .withCopyToContainer(Transferable.of(TRUSTED.caPem), "/tls/ca.crt")
          .withCopyToContainer(Transferable.of(TRUSTED.serverPem), "/tls/server.crt")
          .withCopyToContainer(Transferable.of(TRUSTED.serverKeyPem), "/tls/server.key")
          .withCommand("redis-server", "--port", "0", "--tls-port", "6379", "--tls-cert-file", "/tls/server.crt",
              "--tls-key-file", "/tls/server.key", "--tls-ca-cert-file", "/tls/ca.crt", "--tls-auth-clients", "no");

  @Container
  private static final GenericContainer<?> REDIS =
      new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);

  private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SslAutoConfiguration.class, DataRedisAutoConfiguration.class,
          AuthnServerStorageAutoConfiguration.class))
      .withPropertyValues("authn-server.oidc.enabled=true", "authn-server.oidc.storage.access-tokens=redis",
          "spring.data.redis.timeout=5s", "spring.data.redis.connect-timeout=5s");

  @Test
  void lettuceChecksTheHostNameByDefault() {
    this.tls(TRUSTED, "lettuce").run(context -> assertThat(context).hasFailed().getFailure()
        .hasStackTraceContaining("the Redis connection does not work")
        .hasStackTraceContaining("No subject alternative DNS name matching"));
  }

  @Test
  void lettuceAcceptsATrustedCertificateForAnotherHostWhenTheCheckIsOff() {
    this.tls(TRUSTED, "lettuce").withPropertyValues("authn-server.redis.ssl.skip-hostname-verification=true")
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).getBean(LettuceConnectionFactory.class).isNotNull();
          this.useStore(context.getBean(AccessTokenStore.class));
        });
  }

  @Test
  void lettuceRejectsAnUntrustedIssuerAlsoWhenTheCheckIsOff() {
    this.tls(UNTRUSTED, "lettuce").withPropertyValues("authn-server.redis.ssl.skip-hostname-verification=true")
        .run(context -> assertThat(context).hasFailed().getFailure()
            .hasStackTraceContaining("the Redis connection does not work")
            .hasStackTraceContaining("unable to find valid certification path"));
  }

  @Test
  void jedisChecksTheHostNameByDefault() {
    this.tls(TRUSTED, "jedis").run(context -> assertThat(context).hasFailed().getFailure()
        .hasStackTraceContaining("the Redis connection does not work")
        .hasStackTraceContaining("No subject alternative DNS name matching"));
  }

  @Test
  void jedisAcceptsATrustedCertificateForAnotherHostWhenTheCheckIsOff() {
    this.tls(TRUSTED, "jedis").withPropertyValues("authn-server.redis.ssl.skip-hostname-verification=true")
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).getBean(JedisConnectionFactory.class).isNotNull();
          this.useStore(context.getBean(AccessTokenStore.class));
        });
  }

  @Test
  void jedisRejectsAnUntrustedIssuerAlsoWhenTheCheckIsOff() {
    this.tls(UNTRUSTED, "jedis").withPropertyValues("authn-server.redis.ssl.skip-hostname-verification=true")
        .run(context -> assertThat(context).hasFailed().getFailure()
            .hasStackTraceContaining("the Redis connection does not work")
            .hasStackTraceContaining("unable to find valid certification path"));
  }

  @Test
  void theHostNameSettingDoesNothingWithoutTls() {
    for (final String client : new String[] { "lettuce", "jedis" }) {
      this.runner.withPropertyValues("spring.data.redis.client-type=" + client,
              "spring.data.redis.host=" + REDIS.getHost(), "spring.data.redis.port=" + REDIS.getFirstMappedPort(),
              "authn-server.redis.ssl.skip-hostname-verification=true")
          .run(context -> {
            assertThat(context).hasNotFailed();
            this.useStore(context.getBean(AccessTokenStore.class));
          });
    }
  }

  @Test
  void lettuceTranslatesTheAddressesOfTheNodes() {
    this.runner.withPropertyValues("spring.data.redis.client-type=lettuce",
            "spring.data.redis.host=redis-node.invalid", "spring.data.redis.port=6379",
            "authn-server.redis.cluster.nat-translation[0].from=redis-node.invalid:6379",
            "authn-server.redis.cluster.nat-translation[0].to=%s:%d".formatted(REDIS.getHost(),
                REDIS.getFirstMappedPort()))
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).getBean(AccessTokenStore.class).isInstanceOf(RedisAccessTokenStore.class);
          this.useStore(context.getBean(AccessTokenStore.class));
        });
  }

  @Test
  void natTranslationWithJedisFailsStartup() {
    this.runner.withPropertyValues("spring.data.redis.client-type=jedis",
            "spring.data.redis.host=" + REDIS.getHost(), "spring.data.redis.port=" + REDIS.getFirstMappedPort(),
            "authn-server.redis.cluster.nat-translation[0].from=10.0.0.1:6379",
            "authn-server.redis.cluster.nat-translation[0].to=redis.example.com:6379")
        .run(context -> assertThat(context).hasFailed().getFailure()
            .hasStackTraceContaining("authn-server.redis.cluster.nat-translation is only supported with the Lettuce "
                + "client, and the Redis connection uses Jedis"));
  }

  @Test
  void anInvalidNatTranslationFailsStartup() {
    this.runner.withPropertyValues("spring.data.redis.client-type=lettuce",
            "spring.data.redis.host=" + REDIS.getHost(), "spring.data.redis.port=" + REDIS.getFirstMappedPort(),
            "authn-server.redis.cluster.nat-translation[0].from=10.0.0.1",
            "authn-server.redis.cluster.nat-translation[0].to=redis.example.com:6379")
        .run(context -> assertThat(context).hasFailed().getFailure()
            .hasStackTraceContaining("authn-server.redis.cluster.nat-translation[0].from"));
    this.runner.withPropertyValues("spring.data.redis.client-type=lettuce",
            "spring.data.redis.host=" + REDIS.getHost(), "spring.data.redis.port=" + REDIS.getFirstMappedPort(),
            "authn-server.redis.cluster.nat-translation[0].from=10.0.0.1:6379")
        .run(context -> assertThat(context).hasFailed().getFailure()
            .hasStackTraceContaining("Missing value for authn-server.redis.cluster.nat-translation[0].to"));
  }

  private WebApplicationContextRunner tls(final Certificates trust, final String client) {
    return this.runner.withPropertyValues(
        "spring.data.redis.client-type=" + client,
        "spring.data.redis.host=" + TLS_REDIS.getHost(),
        "spring.data.redis.port=" + TLS_REDIS.getFirstMappedPort(),
        "spring.data.redis.ssl.enabled=true",
        "spring.data.redis.ssl.bundle=redis",
        "spring.ssl.bundle.pem.redis.truststore.certificate=file:" + trust.caFile);
  }

  private void useStore(final AccessTokenStore store) {
    final Instant now = Instant.now();
    final AccessTokenData token =
        new AccessTokenData("t", "rp", "sub", List.of("openid"), "{}", now, now.plusSeconds(60), false, null);
    store.save(token);
    assertThat(store.get("t")).isEqualTo(token);
  }

  /**
   * A CA and a server certificate issued by it for {@value #SERVER_NAME}.
   */
  private static class Certificates {

    final String caPem;

    final String serverPem;

    final String serverKeyPem;

    final Path caFile;

    Certificates(final String caName) {
      try {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        final KeyPair caKeys = generator.generateKeyPair();
        final X500Name ca = new X500Name("CN=" + caName);
        final Date notBefore = Date.from(Instant.now().minus(Duration.ofDays(1)));
        final Date notAfter = Date.from(Instant.now().plus(Duration.ofDays(10)));

        final X509v3CertificateBuilder caBuilder =
            new JcaX509v3CertificateBuilder(ca, BigInteger.ONE, notBefore, notAfter, ca, caKeys.getPublic());
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        caBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        final X509Certificate caCertificate = sign(caBuilder, caKeys.getPrivate());

        final KeyPair serverKeys = generator.generateKeyPair();
        final X509v3CertificateBuilder serverBuilder = new JcaX509v3CertificateBuilder(ca, BigInteger.TWO,
            notBefore, notAfter, new X500Name("CN=" + SERVER_NAME), serverKeys.getPublic());
        serverBuilder.addExtension(Extension.subjectAlternativeName, false,
            new GeneralNames(new GeneralName(GeneralName.dNSName, SERVER_NAME)));
        serverBuilder.addExtension(Extension.keyUsage, true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        serverBuilder.addExtension(Extension.extendedKeyUsage, false,
            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        final X509Certificate serverCertificate = sign(serverBuilder, caKeys.getPrivate());

        this.caPem = pem(caCertificate);
        this.serverPem = pem(serverCertificate);
        this.serverKeyPem = pem(new JcaPKCS8Generator(serverKeys.getPrivate(), null));
        this.caFile = Files.createTempFile("redis-ca", ".crt");
        this.caFile.toFile().deleteOnExit();
        Files.writeString(this.caFile, this.caPem, StandardCharsets.US_ASCII);
      }
      catch (final IOException e) {
        throw new UncheckedIOException(e);
      }
      catch (final Exception e) {
        throw new IllegalStateException(e);
      }
    }

    private static X509Certificate sign(final X509v3CertificateBuilder builder, final PrivateKey key)
        throws Exception {
      return new JcaX509CertificateConverter()
          .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key)));
    }

    private static String pem(final Object object) throws IOException {
      final StringWriter writer = new StringWriter();
      try (final JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
        pemWriter.writeObject(object);
      }
      return writer.toString();
    }
  }

}

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
package se.swedenconnect.spring.authnserver.oidc.client.federation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.oidc.RedisTestNodes;
import se.swedenconnect.spring.authnserver.registry.ClientUpdateResult;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Tests for {@link RedisFederationCache} and the background jobs working on a shared cache, against a Redis container.
 * Two caches with connections of their own play two nodes.
 *
 * @author Martin Lindström
 */
@Testcontainers(disabledWithoutDocker = true)
class RedisFederationCacheTest extends FederationTestSupport {

  @Container
  private static final GenericContainer<?> REDIS = RedisTestNodes.container();

  private static final Duration VALIDITY = Duration.ofMinutes(10);

  private static LettuceConnectionFactory nodeA;

  private static LettuceConnectionFactory nodeB;

  private TestClock clock;

  private StringRedisTemplate template;

  private RedisFederationCache cacheA;

  private RedisFederationCache cacheB;

  @BeforeAll
  static void init() {
    nodeA = RedisTestNodes.connect(REDIS);
    nodeB = RedisTestNodes.connect(REDIS);
  }

  @AfterAll
  static void close() {
    nodeA.destroy();
    nodeB.destroy();
  }

  @BeforeEach
  void setup() {
    RedisTestNodes.flush(nodeA);
    this.clock = new TestClock();
    this.template = new StringRedisTemplate(nodeA);
    this.cacheA = new RedisFederationCache(this.template, "test", this.clock);
    this.cacheB = new RedisFederationCache(new StringRedisTemplate(nodeB), "test", this.clock);
  }

  @Test
  void anEntryPutByOneNodeIsSeenByTheOther() {
    final OIDCClientMetadata metadata = clientMetadata("The Client");
    metadata.setCustomField("organization_identifier", "urn:glue:iso6523:0007:5566778899");
    metadata.setJWKSet(publicKeys(key("rp")));
    final CachedClientRecord record = CachedClientRecord.found(
        new ResolvedClient(CLIENT_ID, metadata, Set.of(MARK_ONE), this.clock.instant().plus(VALIDITY)),
        this.clock.instant(), null)
        .withTrustMark(new TrustMarkRequester.TrustMark(MARK_TWO, this.clock.instant().plusSeconds(120), "a.b.c"));
    this.cacheA.put(record);

    final CachedClientRecord read = this.cacheB.get(CLIENT_ID);
    assertThat(read).isNotNull();
    assertThat(read.clientId()).isEqualTo(CLIENT_ID);
    assertThat(read.metadata().toJSONObject()).isEqualTo(metadata.toJSONObject());
    assertThat(read.metadata().getCustomField("organization_identifier"))
        .isEqualTo("urn:glue:iso6523:0007:5566778899");
    assertThat(read.trustMarkTypes()).containsExactly(MARK_ONE);
    assertThat(read.onDemandTrustMarks()).isEqualTo(record.onDemandTrustMarks());
    assertThat(read.expiresAt()).isEqualTo(record.expiresAt());
    assertThat(read.getMarks(this.clock.instant())).containsExactlyInAnyOrder(MARK_ONE, MARK_TWO);

    assertThat(this.cacheB.getEntries()).extracting(CachedClientRecord::clientId).containsExactly(CLIENT_ID);
    this.cacheB.remove(CLIENT_ID);
    assertThat(this.cacheA.get(CLIENT_ID)).isNull();
    assertThat(this.cacheA.getEntries()).isEmpty();
  }

  @Test
  void theCheckOfAPairwiseClientIsSharedByTheNodes() {
    final String sector = "https://sector.example.com/redirects.json";
    final String callback = CLIENT_ID + "/cb";
    final FederationClientBackendTest.StubResolver resolver = new FederationClientBackendTest.StubResolver();
    resolver.answerFor = id -> new ResolvedClient(id, pairwiseMetadata("The Client", sector, callback), Set.of(),
        this.clock.instant().plus(VALIDITY));
    final StubSectorIdentifierFetcher fetcher = new StubSectorIdentifierFetcher();
    fetcher.documents.put(sector, List.of(callback));
    final FederationClientBackend backendA = new FederationClientBackend(resolver, (id, type) -> null, this.cacheA,
        FederationCacheSettings.defaults(), this.clock);
    final FederationClientBackend backendB = new FederationClientBackend(resolver, (id, type) -> null, this.cacheB,
        FederationCacheSettings.defaults(), this.clock);
    backendA.setPairwiseClientCheck(new PairwiseClientCheck(fetcher));
    backendB.setPairwiseClientCheck(new PairwiseClientCheck(fetcher));

    assertThat(backendA.lookup(CLIENT_ID).isValid()).isTrue();
    assertThat(backendB.update(CLIENT_ID).outcome()).isEqualTo(ClientUpdateResult.Outcome.UPDATED);

    assertThat(resolver.calls).isEqualTo(2);
    assertThat(fetcher.calls).containsExactly(sector);
    assertThat(this.cacheA.get(CLIENT_ID).verifiedSector()).isEqualTo(new VerifiedSector(sector, Set.of(callback)));

    // An invalid mark is seen by both nodes
    fetcher.documents.put(sector, List.of());
    resolver.answerFor = id -> new ResolvedClient(id, pairwiseMetadata("The Client", sector, callback, callback + "2"),
        Set.of(), this.clock.instant().plus(VALIDITY));
    backendA.update(CLIENT_ID);
    assertThat(backendB.lookup(CLIENT_ID).isValid()).isFalse();
    assertThat(backendB.lookup(CLIENT_ID).invalidReason()).contains(callback + "2");
  }

  @Test
  void anEntryForAnUnknownClientIsKept() {
    this.cacheA.put(CachedClientRecord.notFound("unknown", this.clock.instant(), Duration.ofMinutes(1)));
    final CachedClientRecord read = this.cacheB.get("unknown");
    assertThat(read).isNotNull();
    assertThat(read.isFound()).isFalse();
  }

  @Test
  void entriesExpireInRedisAndAreNotHandedOutAfterTheirExpiry() {
    this.cacheA.put(this.found("one", Duration.ofMinutes(10)));
    this.cacheA.put(this.found("two", Duration.ofMinutes(5)));
    assertThat(this.template.getExpire("test:oidc:federation-cache:one")).isBetween(595L, 600L);
    assertThat(this.template.getExpire("test:oidc:federation-cache:two")).isBetween(295L, 300L);
    assertThat(this.template.getExpire("test:oidc:federation-cache-index")).isBetween(595L, 600L);

    this.clock.advance(Duration.ofMinutes(5));
    assertThat(this.cacheB.get("two")).isNull();
    assertThat(this.cacheB.get("one")).isNotNull();
    assertThat(this.cacheB.getEntries()).extracting(CachedClientRecord::clientId).containsExactly("one");

    // Putting an entry drops the expired ones from the index
    this.cacheA.put(this.found("three", Duration.ofMinutes(1)));
    assertThat(this.template.opsForZSet().range("test:oidc:federation-cache-index", 0, -1))
        .containsExactlyInAnyOrder("one", "three");
  }

  @Test
  void anEntryThatCannotBeReadIsIgnored() {
    this.cacheA.put(this.found("one", Duration.ofMinutes(10)));
    this.template.opsForValue().set("test:oidc:federation-cache:one", "{\"clientId\":\"one\",\"metadata\":\"{x\","
        + "\"expiresAt\":\"" + this.clock.instant().plusSeconds(60) + "\"}");
    assertThat(this.cacheA.get("one")).isNull();
    assertThat(this.cacheA.getEntries()).isEmpty();
  }

  @Test
  void theEntityStoreIsSharedByTheNodes() {
    final RedisFederationEntityStore storeA = new RedisFederationEntityStore(this.template, "test", this.clock);
    final RedisFederationEntityStore storeB =
        new RedisFederationEntityStore(new StringRedisTemplate(nodeB), "test", this.clock);
    final OIDCClientMetadata metadata = clientMetadata("The Client");
    final ResolvedEntity entity = new ResolvedEntity(CLIENT_ID, metadata, "https://client.example.com/list",
        Set.of(MARK_ONE), this.clock.instant().plus(Duration.ofHours(1)));
    storeA.put(FederationEntityRecord.found(entity, this.clock.instant(), VALIDITY));
    storeA.put(FederationEntityRecord.notFound("https://unknown.example.com", this.clock.instant(),
        Duration.ofMinutes(1)));
    storeA.put(FederationEntityRecord.found(new ResolvedEntity("https://op.example.com", null, null, Set.of(),
        this.clock.instant().plus(VALIDITY)), this.clock.instant(), null));

    final FederationEntityRecord read = storeB.get(CLIENT_ID);
    assertThat(read).isNotNull();
    assertThat(read.expiresAt()).isEqualTo(this.clock.instant().plus(VALIDITY));
    assertThat(read.listEndpoint()).isEqualTo("https://client.example.com/list");
    assertThat(read.entity().expiresAt()).isEqualTo(entity.expiresAt());
    assertThat(read.entity().trustMarkTypes()).containsExactly(MARK_ONE);
    assertThat(read.toClient().metadata().toJSONObject()).isEqualTo(metadata.toJSONObject());
    assertThat(read.toClient().expiresAt()).isEqualTo(read.expiresAt());
    assertThat(storeB.get("https://unknown.example.com")).isNotNull()
        .satisfies(r -> assertThat(r.isFound()).isFalse());
    assertThat(storeB.get("https://op.example.com")).isNotNull()
        .satisfies(r -> assertThat(r.isFound()).isTrue())
        .satisfies(r -> assertThat(r.toClient()).isNull());
    assertThat(storeB.get("https://never.example.com")).isNull();
    assertThat(this.template.getExpire("test:oidc:federation-entity:" + CLIENT_ID)).isBetween(595L, 600L);

    this.clock.advance(Duration.ofMinutes(2));
    assertThat(storeB.get("https://unknown.example.com")).isNull();
    assertThat(storeB.get(CLIENT_ID)).isNotNull();

    this.template.opsForValue().set("test:oidc:federation-entity:bad", "{\"entityId\":\"bad\",\"found\":true,"
        + "\"clientMetadata\":\"{x\",\"expiresAt\":\"" + this.clock.instant().plusSeconds(60) + "\"}");
    assertThat(storeB.get("bad")).isNull();
  }

  @Test
  void theRetainedClientsAreSharedByTheNodes() {
    final RedisFederationEntityStore storeA = new RedisFederationEntityStore(this.template, "test", this.clock);
    final RedisFederationEntityStore storeB =
        new RedisFederationEntityStore(new StringRedisTemplate(nodeB), "test", this.clock);
    final RetainedClient one = new RetainedClient("one", this.clock.instant(), this.clock.instant().plus(VALIDITY));
    final RetainedClient two =
        new RetainedClient("two", this.clock.instant(), this.clock.instant().plus(Duration.ofHours(1)));

    storeA.putRetainedClient(one);
    storeA.putRetainedClient(two);
    assertThat(storeB.getRetainedClients()).containsExactlyInAnyOrder(one, two);
    assertThat(this.template.getExpire("test:oidc:federation-retained"))
        .isGreaterThan(Duration.ofDays(RedisFederationEntityStore.RETENTION_DAYS).toSeconds());

    storeB.removeRetainedClient("one");
    assertThat(storeA.getRetainedClients()).containsExactly(two);
  }

  @Test
  void aCollectorRunTakesPlaceOnOneNode() {
    final FederationClientBackendTest.StubResolver resolver = new FederationClientBackendTest.StubResolver();
    resolver.answerFor = clientId -> new ResolvedClient(clientId, clientMetadata("The Client"), Set.of(),
        this.clock.instant().plus(VALIDITY));
    final FederationSettings settings = FederationSettings.of(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(key("ta"))),
        new FederationSettings.Resolver(TRUST_ANCHOR, null, null));
    final StubFederationClient client = new StubFederationClient();
    final FederationClientCollector collectorA = new FederationClientCollector(
        new FederationClientBackend(resolver, (id, mark) -> null, this.cacheA, FederationCacheSettings.defaults(),
            this.clock),
        new RedisFederationEntityStore(this.template, "test", this.clock), client, settings,
        FederationCollectorSettings.defaults());
    final FederationClientCollector collectorB = new FederationClientCollector(
        new FederationClientBackend(resolver, (id, mark) -> null, this.cacheB, FederationCacheSettings.defaults(),
            this.clock),
        new RedisFederationEntityStore(new StringRedisTemplate(nodeB), "test", this.clock), client, settings,
        FederationCollectorSettings.defaults());

    assertThat(collectorA.collect()).isNotNull();
    assertThat(collectorB.collect()).isNull();
    assertThat(resolver.asked).containsExactly(TRUST_ANCHOR);
    assertThat(this.cacheB.get(TRUST_ANCHOR)).isNotNull();

    // Releasing the lock, as when the round has passed, lets the next round run
    this.template.delete("test:lock:" + FederationClientCollector.JOB_NAME);
    assertThat(collectorB.collect()).isNotNull();
    assertThat(collectorA.collect()).isNull();
  }

  @Test
  void aTrustMarkStatusRoundRunsOnOneNode() {
    final ECKey issuerKey = key("tmi");
    final FederationSettings settings = new FederationSettings(
        new FederationSettings.TrustAnchor(TRUST_ANCHOR, publicKeys(key("ta"))),
        new FederationSettings.Resolver(TRUST_ANCHOR, URI.create("https://ta.example.com/resolve"), null),
        Map.of(MARK_TWO, new FederationSettings.TrustMarkIssuer(TRUST_MARK_ISSUER,
            URI.create("https://tmi.example.com/trust_mark"), publicKeys(issuerKey),
            URI.create("https://tmi.example.com/trust_mark_status"))));
    final String mark = trustMark(issuerKey, TRUST_MARK_ISSUER, CLIENT_ID, MARK_TWO, null).serialize();
    this.cacheA.put(this.found(CLIENT_ID, Duration.ofDays(1))
        .withTrustMark(new TrustMarkRequester.TrustMark(MARK_TWO, null, mark)));

    final StubFederationClient clientA = new StubFederationClient();
    final StubFederationClient clientB = new StubFederationClient();
    clientA.trustMarkStatusResponse = trustMarkStatus(issuerKey, TRUST_MARK_ISSUER, mark, "revoked");
    clientB.trustMarkStatusResponse = clientA.trustMarkStatusResponse;
    final TrustMarkStatusChecker checkerA =
        new TrustMarkStatusChecker(this.cacheA, settings, clientA, Duration.ofHours(1), this.clock);
    final TrustMarkStatusChecker checkerB =
        new TrustMarkStatusChecker(this.cacheB, settings, clientB, Duration.ofHours(1), this.clock);

    assertThat(checkerA.check() + checkerB.check()).isEqualTo(1);
    assertThat(clientA.trustMarkStatusRequests.size() + clientB.trustMarkStatusRequests.size()).isEqualTo(1);
    assertThat(this.cacheB.get(CLIENT_ID).onDemandTrustMarks()).isEmpty();
    assertThat(this.template.getExpire("test:lock:" + TrustMarkStatusChecker.JOB_NAME)).isBetween(3595L, 3600L);
  }

  @Test
  void invalidArguments() {
    assertThatThrownBy(() -> new RedisFederationCache(null)).isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new RedisFederationCache(this.template, "")).isInstanceOf(IllegalArgumentException.class);
    assertThat(new RedisFederationCache(this.template).getJobLock()).isNotNull();
  }

  private CachedClientRecord found(final String clientId, final Duration validity) {
    return CachedClientRecord.found(new ResolvedClient(clientId, clientMetadata("The Client"), Set.of(),
        this.clock.instant().plus(validity)), this.clock.instant(), null);
  }

}

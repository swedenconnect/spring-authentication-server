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
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Tests for {@link RedisFederationCache}, {@link RedisLookupTracker} and the background jobs working on a shared cache,
 * against a Redis container. Two caches with connections of their own play two nodes.
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
  void lookupCountsAddUpAcrossNodes() {
    final LookupTracker a = this.cacheA.createLookupTracker(100, Duration.ofMinutes(10), this.clock);
    final LookupTracker b = this.cacheB.createLookupTracker(100, Duration.ofMinutes(10), this.clock);
    a.record("frequent");
    b.record("frequent");
    a.record("frequent");
    b.record("second");
    a.record("second");
    b.record("rare");

    assertThat(a.getFrequentClients(2, 10)).containsExactly("frequent", "second");
    assertThat(b.getFrequentClients(3, 10)).containsExactly("frequent");
    assertThat(b.getFrequentClients(1, 1)).containsExactly("frequent");
    assertThat(this.template.getExpire("test:oidc:federation-lookups:frequent")).isBetween(595L, 600L);
    assertThat(this.template.getExpire("test:oidc:federation-lookups")).isBetween(595L, 600L);
  }

  @Test
  void lookupCountsStartOverWhenThePeriodHasPassed() throws Exception {
    final LookupTracker tracker = this.cacheA.createLookupTracker(100, Duration.ofMillis(300), this.clock);
    tracker.record("client");
    tracker.record("client");
    assertThat(tracker.getFrequentClients(2, 10)).containsExactly("client");
    Thread.sleep(400);
    tracker.record("client");
    assertThat(tracker.getFrequentClients(2, 10)).isEmpty();
  }

  @Test
  void theClientNotAskedForInTheLongestTimeIsDroppedFirst() {
    final LookupTracker tracker = this.cacheA.createLookupTracker(2, Duration.ofMinutes(10), this.clock);
    tracker.record("one");
    this.clock.advance(Duration.ofSeconds(1));
    tracker.record("two");
    this.clock.advance(Duration.ofSeconds(1));
    tracker.record("one");
    this.clock.advance(Duration.ofSeconds(1));
    tracker.record("three");

    assertThat(tracker.getFrequentClients(1, 10)).containsExactlyInAnyOrder("one", "three");
  }

  @Test
  void theLookupTrackerChecksItsArguments() {
    assertThatThrownBy(() -> this.cacheA.createLookupTracker(0, Duration.ofMinutes(1), this.clock))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> this.cacheA.createLookupTracker(1, Duration.ZERO, this.clock))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void theBackendCountsLookupsInRedis() throws Exception {
    final FederationClientBackendTest.StubResolver resolver = new FederationClientBackendTest.StubResolver();
    resolver.answerFor = clientId -> new ResolvedClient(clientId, clientMetadata("The Client"), Set.of(),
        this.clock.instant().plus(VALIDITY));
    final FederationCacheSettings settings = FederationCacheSettings.defaults();
    final FederationClientBackend backendA = new FederationClientBackend(resolver, (id, mark) -> null,
        this.cacheA, settings, this.clock);
    final FederationClientBackend backendB = new FederationClientBackend(resolver, (id, mark) -> null,
        this.cacheB, settings, this.clock);

    final RequesterRecord record = backendA.lookup(CLIENT_ID);
    assertThat(record).isNotNull();
    assertThat(backendB.lookup(CLIENT_ID)).isNotNull();
    assertThat(resolver.calls).isEqualTo(1);
    assertThat(backendA.getLookupTracker()).isInstanceOf(RedisLookupTracker.class);
    assertThat(backendB.getLookupTracker().getFrequentClients(2, 10)).containsExactly(CLIENT_ID);
  }

  @Test
  void aRefreshRoundRunsOnOneNode() {
    final FederationCacheSettings settings = new FederationCacheSettings(null,
        FederationCacheSettings.DEFAULT_NOT_FOUND_TIME_TO_LIVE, new FederationCacheSettings.RefreshSettings(true,
            Duration.ofMinutes(1), Duration.ofMinutes(5), 2, Duration.ofMinutes(10), 10, 100));
    final FederationClientBackendTest.StubResolver resolver = new FederationClientBackendTest.StubResolver();
    resolver.answerFor = clientId -> new ResolvedClient(clientId, clientMetadata("The Client"), Set.of(),
        this.clock.instant().plus(VALIDITY));
    final LookupTracker trackerA = this.cacheA.createLookupTracker(100, Duration.ofMinutes(10), this.clock);
    final LookupTracker trackerB = this.cacheB.createLookupTracker(100, Duration.ofMinutes(10), this.clock);
    final FederationCacheRefresher refresherA =
        new FederationCacheRefresher(this.cacheA, resolver, trackerA, settings, this.clock);
    final FederationCacheRefresher refresherB =
        new FederationCacheRefresher(this.cacheB, resolver, trackerB, settings, this.clock);

    this.cacheA.put(this.found("client", VALIDITY));
    trackerA.record("client");
    trackerB.record("client");
    this.clock.advance(Duration.ofMinutes(6));

    final int refreshed = refresherA.refresh() + refresherB.refresh();
    assertThat(refreshed).isEqualTo(1);
    assertThat(resolver.calls).isEqualTo(1);
    assertThat(this.cacheB.get("client").expiresAt()).isEqualTo(this.clock.instant().plus(VALIDITY));

    // Releasing the lock, as when the round has passed, lets the next round run
    this.template.delete("test:lock:" + FederationCacheRefresher.JOB_NAME);
    this.clock.advance(Duration.ofMinutes(6));
    trackerB.record("client");
    trackerA.record("client");
    assertThat(refresherB.refresh() + refresherA.refresh()).isEqualTo(1);
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

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
package se.swedenconnect.spring.authnserver.audit;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.audit.value.MapAuditValue;
import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * The protocol-specific part of an audit event: a named object holding the members that a protocol module supplies,
 * such as the identifiers of the SAML messages or the parameters of an OpenID Connect request. The core writes it as
 * it is, without knowing the protocol.
 * <p>
 * The members are kept in the order they are added. A member without a value is left out. A value is a string, a
 * boolean, an integer, an instant, a list of strings, or a nested object added with
 * {@link Builder#member(ProtocolAuditData)}.
 * </p>
 *
 * @author Martin Lindström
 */
public final class ProtocolAuditData implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The name of the object in the audit event. */
  private final String name;

  /** The members. */
  private final LinkedHashMap<String, Serializable> members;

  /**
   * Constructor.
   *
   * @param name the name of the object in the audit event
   * @param members the members
   */
  private ProtocolAuditData(final @NonNull String name, final @NonNull LinkedHashMap<String, Serializable> members) {
    this.name = name;
    this.members = members;
  }

  /**
   * Creates a builder.
   *
   * @param name the name of the object in the audit event, in snake case
   * @return a {@link Builder}
   */
  public static @NonNull Builder builder(final @NonNull String name) {
    return new Builder(name);
  }

  /**
   * Gets the name of the object in the audit event.
   *
   * @return the name
   */
  public @NonNull String getName() {
    return this.name;
  }

  /**
   * Gets the members.
   *
   * @return an unmodifiable map of the members, in the order they were added
   */
  public @NonNull Map<String, Serializable> getMembers() {
    return Collections.unmodifiableMap(this.members);
  }

  /**
   * Gets the value of a member.
   *
   * @param member the name of the member
   * @return the value, or {@code null} if the member is not present
   */
  public @Nullable Serializable get(final @NonNull String member) {
    return this.members.get(member);
  }

  /**
   * Gets this object as an audit value.
   *
   * @return a {@link MapAuditValue}
   */
  public @NonNull MapAuditValue toAuditValue() {
    return new MapAuditValue(this.name, this.members);
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    return obj instanceof final ProtocolAuditData other
        && this.name.equals(other.name) && this.members.equals(other.members);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.name, this.members);
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String toString() {
    return "%s=%s".formatted(this.name, this.members);
  }

  /**
   * Builder for {@link ProtocolAuditData}.
   */
  public static final class Builder {

    /** The name of the object. */
    private final String name;

    /** The members. */
    private final LinkedHashMap<String, Serializable> members = new LinkedHashMap<>();

    /**
     * Constructor.
     *
     * @param name the name of the object
     */
    private Builder(final @NonNull String name) {
      if (!StringUtils.hasText(name)) {
        throw new IllegalArgumentException("name must be set");
      }
      this.name = name;
    }

    /**
     * Adds a string member. Nothing is added for {@code null} or an empty string.
     *
     * @param member the name of the member
     * @param value the value
     * @return this builder
     */
    public @NonNull Builder member(final @NonNull String member, final @Nullable String value) {
      if (StringUtils.hasText(value)) {
        this.members.put(member, value);
      }
      return this;
    }

    /**
     * Adds a boolean member. Nothing is added for {@code null}.
     *
     * @param member the name of the member
     * @param value the value
     * @return this builder
     */
    public @NonNull Builder member(final @NonNull String member, final @Nullable Boolean value) {
      if (value != null) {
        this.members.put(member, value);
      }
      return this;
    }

    /**
     * Adds an integer member. Nothing is added for {@code null}.
     *
     * @param member the name of the member
     * @param value the value
     * @return this builder
     */
    public @NonNull Builder member(final @NonNull String member, final @Nullable Integer value) {
      if (value != null) {
        this.members.put(member, value);
      }
      return this;
    }

    /**
     * Adds an instant member. Nothing is added for {@code null}.
     *
     * @param member the name of the member
     * @param value the value
     * @return this builder
     */
    public @NonNull Builder member(final @NonNull String member, final @Nullable Instant value) {
      if (value != null) {
        this.members.put(member, value);
      }
      return this;
    }

    /**
     * Adds a member holding a list of strings. Nothing is added for {@code null} or an empty list.
     *
     * @param member the name of the member
     * @param values the values
     * @return this builder
     */
    public @NonNull Builder member(final @NonNull String member, final @Nullable Collection<String> values) {
      if (values != null && !values.isEmpty()) {
        this.members.put(member, new ArrayList<>(values));
      }
      return this;
    }

    /**
     * Adds a nested object, under its own name. Nothing is added for {@code null} or an object without members.
     *
     * @param value the nested object
     * @return this builder
     */
    public @NonNull Builder member(final @Nullable ProtocolAuditData value) {
      if (value != null && !value.members.isEmpty()) {
        this.members.put(value.name, new LinkedHashMap<>(value.members));
      }
      return this;
    }

    /**
     * Builds the object.
     *
     * @return a {@link ProtocolAuditData}
     */
    public @NonNull ProtocolAuditData build() {
      return new ProtocolAuditData(this.name, new LinkedHashMap<>(this.members));
    }
  }

}

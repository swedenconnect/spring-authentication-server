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
package se.swedenconnect.spring.authnserver.attributes;

import java.io.Serializable;

import org.jspecify.annotations.NonNull;

/**
 * Protocol data that decides for itself what happens when two requested attributes carrying it are merged.
 * <p>
 * Merging two {@link GenericRequestedAttribute}s lets the data of the second attribute replace the data of the first
 * one, key by key. Data that implements this interface is merged instead. The generic layer still never looks at what
 * the data means, it only asks it to merge.
 * </p>
 * <p>
 * The delivery target of an OpenID Connect claim is such data: a claim that one source asks for in the ID token and
 * another asks for from the UserInfo endpoint is delivered in both places.
 * </p>
 *
 * @author Martin Lindström
 */
public interface MergeableProtocolData extends Serializable {

  /**
   * Merges this piece of protocol data with another piece stored under the same key.
   *
   * @param other the data to merge with
   * @return the merged data
   */
  @NonNull Serializable mergeWith(final @NonNull Serializable other);

}

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
package se.swedenconnect.spring.authnserver.oidc.attributes;

/**
 * Where a requested claim is to be delivered.
 * <p>
 * This is carried as protocol data on a
 * {@link se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute} under the key
 * {@link #PROTOCOL_DATA_KEY}. The generic layer never looks at it.
 * </p>
 *
 * @author Martin Lindström
 */
public enum ClaimDeliveryTarget {

  /** The claim is to be delivered in the ID token. */
  ID_TOKEN,

  /** The claim is to be delivered from the UserInfo endpoint. */
  USER_INFO;

  /** The key under which the delivery target is stored as protocol data. */
  public static final String PROTOCOL_DATA_KEY = "oidc.delivery-target";

}

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
package se.swedenconnect.spring.authnserver.sso;

/**
 * The kind of a refusal to reuse a previous authentication. It decides which error an OpenID Connect requester gets
 * when it asked for a passive authentication that could not be answered from a previous one.
 *
 * @author Martin Lindström
 */
public enum SsoDenialKind {

  /** The user has to authenticate again. Reported to an OpenID Connect requester as {@code login_required}. */
  LOGIN_REQUIRED,

  /**
   * The user has to be asked something, even though the authentication itself could have been reused. Reported to an
   * OpenID Connect requester as {@code interaction_required}.
   */
  INTERACTION_REQUIRED

}

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

/**
 * The storage of the authentications that a redirect provider has in progress. The flow and the module's controller
 * see one side each, {@link RedirectFlowRepository} and {@link RedirectAuthenticatorRepository}, but the two sides work
 * on the same data and are therefore one object.
 * <p>
 * {@link SessionBasedRedirectAuthenticationRepository} is the default. An implementation of its own must keep the
 * authentications apart per identifier, must let them expire, and must store nothing that does not survive Java
 * serialization.
 * </p>
 *
 * @author Martin Lindström
 */
public interface RedirectAuthenticationRepository extends RedirectFlowRepository, RedirectAuthenticatorRepository {
}

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
package se.swedenconnect.spring.authnserver.job;

import java.time.Duration;

import org.jspecify.annotations.NonNull;

/**
 * Decides which node runs a round of a background job, so that a job that works on state shared by several nodes runs
 * on one node at a time.
 * <p>
 * A node that gets the lock holds it for the given lease, also after the round has finished, so that no other node
 * runs the same round again. The lease is normally the interval of the job. A node that holds the lock and asks again
 * gets it again, and its lease starts over. A node that stops while holding the lock blocks the job for at most one
 * lease.
 * </p>
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface JobLock {

  /**
   * A lock that is always granted. It is what a job uses when its state is kept in the memory of one node, or when
   * there is only one node.
   */
  JobLock LOCAL = (job, lease) -> true;

  /**
   * Tries to get the lock for a job.
   *
   * @param job the name of the job
   * @param lease how long the lock is held, unless the same node asks again
   * @return {@code true} if the lock was granted, and the round should run on this node, and {@code false} if
   *     another node holds it
   */
  boolean tryAcquire(final @NonNull String job, final @NonNull Duration lease);

}

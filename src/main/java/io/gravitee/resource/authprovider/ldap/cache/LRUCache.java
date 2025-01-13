/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
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
package io.gravitee.resource.authprovider.ldap.cache;

import com.google.common.hash.Hashing;
import io.gravitee.resource.authprovider.api.Authentication;
import java.io.Serial;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class LRUCache {

    /**
     * Initial capacity of the hash map.
     */
    private static final int INITIAL_CAPACITY = 16;

    /**
     * Load factor of the hash map.
     */
    private static final float LOAD_FACTOR = 0.75f;

    /**
     * Map to cache authentication results.
     */
    private final Map<String, Item> cache;

    /**
     * Executor for performing eviction.
     */
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(r -> { // CheckStyle:JavadocVariable OFF
        final Thread t = new Thread(r);
        t.setDaemon(true);
        return t;
    });

    // CheckStyle:JavadocVariable ON

    /**
     * Creates a new LRU cache.
     *
     * @param size       number of results to cache
     * @param timeToLive that results should stay in the cache
     * @param interval   to enforce timeToLive
     */
    public LRUCache(final int size, final Duration timeToLive, final Duration interval) {
        cache =
            new LinkedHashMap<>(INITIAL_CAPACITY, LOAD_FACTOR, true) {
                @Serial
                private static final long serialVersionUID = -4082551016104288539L;

                @Override
                protected boolean removeEldestEntry(Map.Entry eldest) {
                    return size() > size;
                }
            };

        final Runnable expire = () -> {
            synchronized (cache) {
                final Iterator<Item> i = cache.values().iterator();
                final Instant now = Instant.now();
                while (i.hasNext()) {
                    final Item item = i.next();
                    if (Duration.between(item.creationTime, now).compareTo(timeToLive) > 0) {
                        i.remove();
                    }
                }
            }
        };
        executor.scheduleAtFixedRate(expire, interval.toMillis(), interval.toMillis(), TimeUnit.MILLISECONDS);
    }

    /**
     * Removes all data from this cache.
     */
    public void clear() {
        synchronized (cache) {
            cache.clear();
        }
    }

    public Authentication get(final Key key) {
        synchronized (cache) {
            String hash = key.asHash();
            if (cache.containsKey(hash)) {
                return cache.get(hash).result;
            } else {
                return null;
            }
        }
    }

    public void put(final Key key, final Authentication response) {
        synchronized (cache) {
            cache.put(key.asHash(), new Item(response));
        }
    }

    /**
     * Returns the number of items in this cache.
     *
     * @return size of this cache
     */
    public int size() {
        synchronized (cache) {
            return cache.size();
        }
    }

    /**
     * Frees any resources associated with this cache.
     */
    public void close() {
        executor.shutdown();
    }

    /**
     * Represents the cache key, not stored as is but hashed using {@link #asHash()}
     * @param username
     * @param password
     */
    public record Key(String username, String password) {
        String asHash() {
            return Hashing.sha256().hashBytes(username.concat("/").concat(password).getBytes()).toString();
        }
    }

    /**
     * Container for data related to cached ldap authentication results.
     * @param result auth object
     * @param creationTime timestamp when this item is created
     */
    private record Item(Authentication result, Instant creationTime) {
        Item(final Authentication authentication) {
            this(authentication, Instant.now());
        }
    }
}

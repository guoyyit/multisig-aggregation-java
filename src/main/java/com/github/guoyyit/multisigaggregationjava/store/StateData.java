package com.github.guoyyit.multisigaggregationjava.store;

import com.github.guoyyit.multisigaggregationjava.domain.RegisteredKey;
import com.github.guoyyit.multisigaggregationjava.domain.SignSession;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Snapshot of all durable service state, serialized atomically to a JSON file.
 *
 * @param version            state format version
 * @param keys               key id -> registration
 * @param sessions           session id -> session state
 * @param usedNonceTuples    session id -> round -> key id -> committed tuple hex
 * @param consumedPartialKey key -> session id/round of the unique (R1,R2,m) tuple already consumed
 */
public record StateData(
        int version,
        Map<String, RegisteredKey> keys,
        Map<String, SignSession> sessions,
        Map<String, Map<Integer, Map<String, String>>> usedNonceTuples,
        Map<String, String> consumedPartialKey
) {

    public static StateData empty() {
        return new StateData(1, new LinkedHashMap<>(), new LinkedHashMap<>(),
                new LinkedHashMap<>(), new LinkedHashMap<>());
    }
}

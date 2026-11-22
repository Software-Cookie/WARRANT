package io.warrant.core.warrant;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.warrant.core.crypto.Digests;
import io.warrant.core.ids.Ids;

import java.util.LinkedHashMap;
import java.util.Map;

/** A child's reference to its parent. Covered by the child's signature. */
public record ParentRef(@JsonProperty("wid") String wid, @JsonProperty("digest") String digest) {

    public ParentRef {
        if (!Ids.isWellFormed(wid, "wrt")) {
            throw new IllegalArgumentException("parent.wid malformed");
        }
        if (!Digests.isWellFormed(digest)) {
            throw new IllegalArgumentException("parent.digest malformed");
        }
    }

    Map<String, Object> toCanonicalMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("digest", digest);
        map.put("wid", wid);
        return map;
    }
}

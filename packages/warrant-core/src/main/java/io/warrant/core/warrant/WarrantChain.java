package io.warrant.core.warrant;

import java.util.ArrayList;
import java.util.List;

/**
 * A delegation chain, root first. Carried whole in the {@code X-Warrant} header ({@code link~link~link}) so the
 * gateway can check the narrowing invariant between every pair of links without fetching any parent.
 */
public record WarrantChain(List<SignedWarrant> links) {

    public static final int MAX_ENCODED_LENGTH = 32 * 1024;
    public static final int MAX_LINKS = Warrant.MAX_HOPS + 1;

    public WarrantChain {
        if (links == null || links.isEmpty()) {
            throw new IllegalArgumentException("chain must contain at least one warrant");
        }
        if (links.size() > MAX_LINKS) {
            throw new IllegalArgumentException("chain exceeds " + MAX_LINKS + " links");
        }
        links = List.copyOf(links);
    }

    public static WarrantChain parse(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            throw new WarrantCodec.MalformedWarrantException("warrant header is empty");
        }
        if (encoded.length() > MAX_ENCODED_LENGTH) {
            throw new WarrantCodec.MalformedWarrantException("warrant header too long");
        }
        String[] parts = encoded.split("~", -1);
        if (parts.length > MAX_LINKS) {
            throw new WarrantCodec.MalformedWarrantException("chain exceeds " + MAX_LINKS + " links");
        }
        List<SignedWarrant> links = new ArrayList<>(parts.length);
        for (String part : parts) {
            links.add(SignedWarrant.parse(part));
        }
        return new WarrantChain(links);
    }

    public SignedWarrant root() {
        return links.get(0);
    }

    public SignedWarrant leaf() {
        return links.get(links.size() - 1);
    }

    /** Delegation depth of the leaf: 0 for a human-issued warrant. */
    public int depth() {
        return links.size() - 1;
    }

    public WarrantChain append(SignedWarrant child) {
        List<SignedWarrant> extended = new ArrayList<>(links);
        extended.add(child);
        return new WarrantChain(extended);
    }

    public String encode() {
        StringBuilder out = new StringBuilder();
        for (SignedWarrant link : links) {
            if (!out.isEmpty()) {
                out.append('~');
            }
            out.append(link.token());
        }
        return out.toString();
    }

    public List<String> wids() {
        List<String> wids = new ArrayList<>(links.size());
        for (SignedWarrant link : links) {
            wids.add(link.claims().wid());
        }
        return wids;
    }
}

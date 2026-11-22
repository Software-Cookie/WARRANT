package io.warrant.cp.internal;

import jakarta.servlet.http.HttpServletRequest;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/** Development-only: trusts callers whose socket address is inside the configured CIDR ranges. */
public final class NetworkCallerVerifier implements InternalCallerVerifier {

    private record Cidr(BigInteger network, BigInteger mask, int length) {
        boolean contains(InetAddress address) {
            byte[] bytes = address.getAddress();
            if (bytes.length * 8 != length) {
                return false;
            }
            return new BigInteger(1, bytes).and(mask).equals(network);
        }
    }

    private final List<Cidr> allowed;

    public NetworkCallerVerifier(List<String> cidrs) {
        this.allowed = cidrs.stream().map(String::trim).filter(s -> !s.isEmpty()).map(NetworkCallerVerifier::parse).toList();
    }

    private static Cidr parse(String cidr) {
        String[] parts = cidr.split("/");
        try {
            byte[] bytes = InetAddress.getByName(parts[0]).getAddress();
            int bits = bytes.length * 8;
            int prefix = parts.length == 2 ? Integer.parseInt(parts[1]) : bits;
            BigInteger mask = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE)
                    .shiftRight(bits - prefix).shiftLeft(bits - prefix);
            return new Cidr(new BigInteger(1, bytes).and(mask), mask, bits);
        } catch (UnknownHostException | NumberFormatException e) {
            throw new IllegalArgumentException("invalid CIDR " + cidr);
        }
    }

    @Override
    public boolean isTrustedCaller(HttpServletRequest request) {
        try {
            InetAddress address = InetAddress.getByName(request.getRemoteAddr());
            return allowed.stream().anyMatch(cidr -> cidr.contains(address));
        } catch (UnknownHostException e) {
            return false;
        }
    }
}

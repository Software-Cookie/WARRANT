package io.warrant.pep.pipeline;

import io.warrant.core.warrant.SignedWarrant;
import io.warrant.core.warrant.Warrant;
import io.warrant.core.warrant.WarrantChain;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

/**
 * Cumulative ceilings. Usage is charged to every warrant in the delegation chain in one atomic Redis script, so
 * neither salami slicing (many small calls) nor fanning out across subagents can exceed any link's ceiling.
 */
@Component
public class UsageLedger {

    // KEYS: rows key per link, then spend key per link.
    // ARGV: link count, rows to add, spend to add, ttl seconds, row ceilings per link, spend ceilings per link.
    private static final String CHARGE = """
            local n = tonumber(ARGV[1])
            local rows = tonumber(ARGV[2])
            local spend = tonumber(ARGV[3])
            local ttl = tonumber(ARGV[4])
            for i = 1, n do
              local usedRows = tonumber(redis.call('GET', KEYS[i]) or '0')
              local usedSpend = tonumber(redis.call('GET', KEYS[n + i]) or '0')
              if usedRows + rows > tonumber(ARGV[4 + i]) or usedSpend + spend > tonumber(ARGV[4 + n + i]) then
                return {0, i, usedRows, usedSpend}
              end
            end
            for i = 1, n do
              redis.call('INCRBY', KEYS[i], rows)
              redis.call('EXPIRE', KEYS[i], ttl)
              redis.call('INCRBY', KEYS[n + i], spend)
              redis.call('EXPIRE', KEYS[n + i], ttl)
            end
            return {1, 0, 0, 0}
            """;

    private final StringRedisTemplate redis;
    private final Clock clock;
    @SuppressWarnings("rawtypes")
    private final DefaultRedisScript<List> charge = new DefaultRedisScript<>(CHARGE, List.class);

    public UsageLedger(StringRedisTemplate redis, Clock clock) {
        this.redis = redis;
        this.clock = clock;
    }

    public record Usage(long rowsUsed, long spendUsed) {
    }

    /**
     * Effective usage relative to the leaf's ceiling: the binding constraint across the chain, expressed so that
     * {@code used + rows > leaf ceiling} is exactly "this charge would fail".
     */
    public Usage usage(WarrantChain chain) {
        List<String> keys = new ArrayList<>();
        for (SignedWarrant link : chain.links()) {
            keys.add(rowsKey(link.claims().wid()));
            keys.add(spendKey(link.claims().wid()));
        }
        List<String> values = redis.opsForValue().multiGet(keys);
        Warrant leaf = chain.leaf().claims();
        long rowsRemaining = Long.MAX_VALUE;
        long spendRemaining = Long.MAX_VALUE;
        for (int i = 0; i < chain.links().size(); i++) {
            Warrant link = chain.links().get(i).claims();
            long usedRows = parse(values == null ? null : values.get(2 * i));
            long usedSpend = parse(values == null ? null : values.get(2 * i + 1));
            rowsRemaining = Math.min(rowsRemaining, link.ceiling().rows() - usedRows);
            spendRemaining = Math.min(spendRemaining, link.ceiling().spend() - usedSpend);
        }
        return new Usage(Math.max(0, leaf.ceiling().rows() - rowsRemaining),
                Math.max(0, leaf.ceiling().spend() - spendRemaining));
    }

    /** Atomically charges every link; false when any link's ceiling would be exceeded (nothing is charged). */
    @SuppressWarnings("unchecked")
    public boolean charge(WarrantChain chain, long rows, long spend) {
        if (rows <= 0 && spend <= 0) {
            return true;
        }
        int n = chain.links().size();
        List<String> keys = new ArrayList<>(2 * n);
        List<String> args = new ArrayList<>();
        for (SignedWarrant link : chain.links()) {
            keys.add(rowsKey(link.claims().wid()));
        }
        for (SignedWarrant link : chain.links()) {
            keys.add(spendKey(link.claims().wid()));
        }
        long ttl = Math.max(60, chain.leaf().claims().exp() - clock.instant().getEpochSecond() + 3600);
        args.add(String.valueOf(n));
        args.add(String.valueOf(Math.max(0, rows)));
        args.add(String.valueOf(Math.max(0, spend)));
        args.add(String.valueOf(ttl));
        chain.links().forEach(l -> args.add(String.valueOf(l.claims().ceiling().rows())));
        chain.links().forEach(l -> args.add(String.valueOf(l.claims().ceiling().spend())));
        List<Object> result = redis.execute(charge, keys, args.toArray());
        return result != null && !result.isEmpty() && ((Number) result.get(0)).longValue() == 1L;
    }

    /** Records usage a human approved beyond the ceiling, without a limit check. */
    public void chargeApproved(WarrantChain chain, long rows) {
        long ttl = Math.max(60, chain.leaf().claims().exp() - clock.instant().getEpochSecond() + 3600);
        for (SignedWarrant link : chain.links()) {
            redis.opsForValue().increment(rowsKey(link.claims().wid()), Math.max(0, rows));
            redis.expire(rowsKey(link.claims().wid()), java.time.Duration.ofSeconds(ttl));
        }
    }

    private static long parse(String value) {
        return value == null ? 0 : Long.parseLong(value);
    }

    private static String rowsKey(String wid) {
        return "warrant:usage:rows:" + wid;
    }

    private static String spendKey(String wid) {
        return "warrant:usage:spend:" + wid;
    }
}

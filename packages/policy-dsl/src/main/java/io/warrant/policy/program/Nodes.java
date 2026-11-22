package io.warrant.policy.program;

import io.warrant.core.warrant.Scope;
import io.warrant.policy.ActionFacts;

import java.util.List;

/**
 * Evaluation nodes. Booleans are three-valued ({@link #TRUE}, {@link #FALSE}, {@link #UNKNOWN}) so that a rule
 * depending on a fact L1 cannot know yields UNKNOWN instead of a guess. Nodes read facts directly and allocate
 * nothing on the evaluation path.
 */
public final class Nodes {

    public static final byte FALSE = 0;
    public static final byte TRUE = 1;
    public static final byte UNKNOWN = 2;

    private Nodes() {
    }

    public interface BoolNode {
        byte test(ActionFacts facts);
    }

    public interface NumNode {
        boolean known(ActionFacts facts);

        double value(ActionFacts facts);
    }

    public interface StrNode {
        /** Null when unknown. */
        String value(ActionFacts facts);
    }

    public interface ListNode {
        /** Null when unknown. */
        List<String> value(ActionFacts facts);
    }

    static byte of(boolean value) {
        return value ? TRUE : FALSE;
    }

    // -------------------------------------------------------------------- literals

    record BoolConst(byte value) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            return value;
        }
    }

    record NumConst(double constant) implements NumNode {
        @Override
        public boolean known(ActionFacts facts) {
            return true;
        }

        @Override
        public double value(ActionFacts facts) {
            return constant;
        }
    }

    record StrConst(String constant) implements StrNode {
        @Override
        public String value(ActionFacts facts) {
            return constant;
        }
    }

    record ListConst(List<String> constant) implements ListNode {
        @Override
        public List<String> value(ActionFacts facts) {
            return constant;
        }
    }

    // -------------------------------------------------------------------- facts

    record NumFact(FactId fact) implements NumNode {
        @Override
        public boolean known(ActionFacts facts) {
            return fact.numKnown(facts);
        }

        @Override
        public double value(ActionFacts facts) {
            return fact.num(facts);
        }
    }

    record StrFact(FactId fact) implements StrNode {
        @Override
        public String value(ActionFacts facts) {
            return fact.str(facts);
        }
    }

    record BoolFact(FactId fact) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            return of(fact.bool(facts));
        }
    }

    record ListFact(FactId fact) implements ListNode {
        @Override
        public List<String> value(ActionFacts facts) {
            return fact.list(facts);
        }
    }

    // Tenant settings are typed at the point of use; a value of the wrong type is unknown, never coerced.

    record TenantNum(String key) implements NumNode {
        @Override
        public boolean known(ActionFacts facts) {
            return facts.tenantSettings().get(key) instanceof Number;
        }

        @Override
        public double value(ActionFacts facts) {
            return facts.tenantSettings().get(key) instanceof Number n ? n.doubleValue() : 0;
        }
    }

    record TenantStr(String key) implements StrNode {
        @Override
        public String value(ActionFacts facts) {
            return facts.tenantSettings().get(key) instanceof String s ? s : null;
        }
    }

    record TenantList(String key) implements ListNode {
        @Override
        public List<String> value(ActionFacts facts) {
            if (!(facts.tenantSettings().get(key) instanceof List<?> list)) {
                return null;
            }
            for (Object element : list) {
                if (!(element instanceof String)) {
                    return null;
                }
            }
            @SuppressWarnings("unchecked")
            List<String> strings = (List<String>) list;
            return strings;
        }
    }

    record TenantBool(String key) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            return facts.tenantSettings().get(key) instanceof Boolean b ? of(b) : UNKNOWN;
        }
    }

    // -------------------------------------------------------------------- operators

    record And(BoolNode[] operands) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            boolean unknown = false;
            for (BoolNode operand : operands) {
                byte value = operand.test(facts);
                if (value == FALSE) {
                    return FALSE;
                }
                if (value == UNKNOWN) {
                    unknown = true;
                }
            }
            return unknown ? UNKNOWN : TRUE;
        }
    }

    record Or(BoolNode[] operands) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            boolean unknown = false;
            for (BoolNode operand : operands) {
                byte value = operand.test(facts);
                if (value == TRUE) {
                    return TRUE;
                }
                if (value == UNKNOWN) {
                    unknown = true;
                }
            }
            return unknown ? UNKNOWN : FALSE;
        }
    }

    record Not(BoolNode operand) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            byte value = operand.test(facts);
            return value == UNKNOWN ? UNKNOWN : (value == TRUE ? FALSE : TRUE);
        }
    }

    enum Cmp {
        LT, LE, GT, GE
    }

    record NumCompare(Cmp cmp, NumNode left, NumNode right) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            if (!left.known(facts) || !right.known(facts)) {
                return UNKNOWN;
            }
            double l = left.value(facts);
            double r = right.value(facts);
            return of(switch (cmp) {
                case LT -> l < r;
                case LE -> l <= r;
                case GT -> l > r;
                case GE -> l >= r;
            });
        }
    }

    record NumEquals(NumNode left, NumNode right, boolean negate) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            if (!left.known(facts) || !right.known(facts)) {
                return UNKNOWN;
            }
            return of((left.value(facts) == right.value(facts)) != negate);
        }
    }

    record StrEquals(StrNode left, StrNode right, boolean negate) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            String l = left.value(facts);
            String r = right.value(facts);
            if (l == null || r == null) {
                return UNKNOWN;
            }
            return of(l.equals(r) != negate);
        }
    }

    record BoolEquals(BoolNode left, BoolNode right, boolean negate) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            byte l = left.test(facts);
            byte r = right.test(facts);
            if (l == UNKNOWN || r == UNKNOWN) {
                return UNKNOWN;
            }
            return of((l == r) != negate);
        }
    }

    record StrIn(StrNode left, ListNode right, boolean negate) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            String l = left.value(facts);
            List<String> r = right.value(facts);
            if (l == null || r == null) {
                return UNKNOWN;
            }
            return of(r.contains(l) != negate);
        }
    }

    /** {@code list in other} is true when every element is in {@code other}; {@code not in} when any is not. */
    record ListIn(ListNode left, ListNode right, boolean negate) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            List<String> l = left.value(facts);
            List<String> r = right.value(facts);
            if (l == null || r == null) {
                return UNKNOWN;
            }
            boolean all = true;
            for (String element : l) {
                if (!r.contains(element)) {
                    all = false;
                    break;
                }
            }
            return of(all != negate);
        }
    }

    // -------------------------------------------------------------------- functions

    record ScopeHas(StrNode permission) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            String p = permission.value(facts);
            return p == null ? UNKNOWN : of(Scope.anyCovers(facts.scope(), p));
        }
    }

    record TargetTagged(StrNode tag) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            String t = tag.value(facts);
            return t == null ? UNKNOWN : of(facts.targetTags().contains(t));
        }
    }

    record AffectedAny(List<String> classes) implements BoolNode {
        @Override
        public byte test(ActionFacts facts) {
            List<String> found = facts.protectedClasses();
            if (found == null) {
                return UNKNOWN;
            }
            for (String protectedClass : classes) {
                if (found.contains(protectedClass)) {
                    return TRUE;
                }
            }
            return FALSE;
        }
    }
}

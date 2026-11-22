package io.warrant.pep;

import io.warrant.core.warrant.SignedWarrant;

import java.util.List;

public final class GatewayTestAccess {

    private GatewayTestAccess() {
    }

    public static SignedWarrant child(SignedWarrant parent, long rows) {
        return GatewayTest.WORLD.warrants.sign(GatewayTest.WORLD.warrants.childClaims(parent,
                List.copyOf(parent.claims().scope()), rows, parent.claims().exp(), parent.claims().hops() - 1));
    }
}

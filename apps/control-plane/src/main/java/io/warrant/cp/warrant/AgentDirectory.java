package io.warrant.cp.warrant;

import java.util.List;
import java.util.Optional;

public interface AgentDirectory {

    Optional<Agent> find(String tenant, String name);

    List<Agent> list(String tenant);

    void register(Agent agent);

    void suspend(String tenant, String name);
}

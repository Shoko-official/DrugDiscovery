package bioworld.toolbroker

default allow := false

allow if {
  input.capability.expires_at_ns > time.now_ns()
  input.capability.session_id == input.session_id
  input.tool.id in input.capability.allowed_tools
  input.estimated_cost_eur <= input.capability.remaining_budget_eur
  not input.data_classification == "biosecurity-restricted"
}

require_approval if {
  input.tool.effect in {"physical", "irreversible", "external_write"}
}

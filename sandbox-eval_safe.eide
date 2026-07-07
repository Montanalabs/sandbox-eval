#! Sandboxed code-eval gate — untrusted a snippet can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires runSandbox — the sandboxed code-eval gate sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant runSandbox

type SandOp = MathOp | StrOp | ListOp
type Decision = RunSand(SandOp) | RejectEval

let raw = fetch<web>  # UNTRUSTED a snippet — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
using runSandbox { privileged { runSandbox(d) } }  # act on the trusted decision only

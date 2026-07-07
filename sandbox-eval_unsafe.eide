#! VULNERABLE sandbox-eval — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant runSandbox

let raw = fetch<web>
using runSandbox { privileged { runSandbox(raw) } }  # tainted -> tool: REJECTED

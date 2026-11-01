# Agentic AI Governance and Security

Companion code for the book **Agentic AI Governance and Security: A
Hands-On Guide to Threat Modeling, Access Control, Injection Defense
and Compliance for AI Agents** by Nachiketh Murthy.

An agent that reads email, searches documents and calls tools can be
steered by the content it reads. This repository shows, end to end,
how to secure and govern such an agent: each package is a small,
readable reference implementation of one control, with a runnable
example and tests.

Everything runs offline against a fake enterprise (customers, an
inbox, web pages, email, refunds, a code runner) and a scripted model
that can be made to follow injected instructions. The running attack:
a poisoned email steers the support agent into exporting every
customer record and emailing it to an attacker. Each chapter's example
shows a control stopping it, reproducibly.

> Defensive, educational code. Attacks are simulated in memory against
> the repository's own fake environment. Controls reduce risk; none
> eliminates it. Nothing here is legal or compliance advice.

## Quick start

```bash
git clone https://github.com/manifoldailearning/agentic-ai-governance-security
cd agentic-ai-governance-security
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"      # Python 3.11+, no runtime dependencies
pytest -q
python examples/ch01_attack_surface.py
```

The `ags` command runs the security gate used in CI:

```bash
ags assess --gate            # launch review; non-zero exit if blocked
ags assess --config basic    # see what a weaker setup fails
ags redteam                  # attack success rate per defense set
ags threats                  # top threats from the threat model
```

## Control map

| Ch | Control | Package | Example |
|----|---------|---------|---------|
| 1 | The agent attack surface | `ags.core` | `ch01_attack_surface.py` |
| 2 | Threat modeling | `ags.threat` | `ch02_threat_model.py` |
| 3 | Agent identity and delegation | `ags.identity` | `ch03_agent_identity.py` |
| 4 | Least-privilege tool access | `ags.authz` | `ch04_authorization.py` |
| 5 | Secrets and credential brokering | `ags.secrets` | `ch05_secrets.py` |
| 6 | Prompt injection defense | `ags.injection` | `ch06_prompt_injection.py` |
| 7 | Information flow control | `ags.flow` | `ch07_information_flow.py` |
| 8 | Sandboxing and egress control | `ags.sandbox` | `ch08_sandboxing.py` |
| 9 | Data loss prevention | `ags.dlp` | `ch09_data_loss_prevention.py` |
| 10 | Secure retrieval and memory | `ags.memory` | `ch10_memory.py` |
| 11 | Privacy by design | `ags.privacy` | `ch11_privacy.py` |
| 12 | Human oversight and approvals | `ags.oversight` | `ch12_oversight.py` |
| 13 | Red teaming | `ags.redteam` | `ch13_red_team.py` |
| 14 | Detection | `ags.detect` | `ch14_detection.py` |
| 15 | Incident response | `ags.respond` | `ch15_incident_response.py` |
| 16 | Policy as code | `ags.policy` | `ch16_policy_as_code.py` |
| 17 | Audit trails and evidence | `ags.audit` | `ch17_audit_evidence.py` |
| 18 | Risk and compliance mapping | `ags.risk` | `ch18_risk_compliance.py` |
| 19 | AI supply chain security | `ags.supply` | `ch19_supply_chain.py` |
| 20 | Governance program and launch review | `ags.program` | `ch20_governance_program.py` |

## Design notes

- **The model proposes; the runtime decides.** Every tool call passes
  a chain of guards (`ags.core.runtime`). The first deny wins; an
  approve verdict needs a human approver.
- **Labels travel with data.** Tool results carry labels such as
  `untrusted`, `pii` and `bulk` into the run's context, so later
  guards know what the agent has seen.
- **Every decision is an event.** Detection, forensics, audit and
  evidence all read the same stream.
- **Example keys are examples.** Keys, thresholds and framework
  mappings in the code are illustrative and labeled as such.

## Learn more

- Part of a series with *Agentic AI Deployment Patterns for
  Production* and *Agentic Ops for Production*.
- Live program: [Agentic AI Enterprise Mastery Bootcamp](https://manifoldailearning.com/services/agenticaibootcamp)
- [manifoldailearning.com](https://manifoldailearning.com)

## License

MIT. See [LICENSE](LICENSE).

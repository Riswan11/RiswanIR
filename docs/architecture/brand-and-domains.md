# Riswan Labs and Riswan IR

**Riswan Labs** is the parent brand. Its tagline is “Engineering the Future of Security.”

**Riswan IR** is the flagship incident response product. Its tagline is “Evidence-Driven. Intelligence-Powered.” The product identifier is `ir`. The current workspace provides deterministic detection, evidence custody, identity and temporal correlation, risk scoring and historical memory. Autonomous investigation is planned.

## Brand assets

| Brand | Light background | Dark background | Favicons |
| --- | --- | --- | --- |
| Riswan Labs | [SVG lockup](../../src/riswan_ir/frontend/labs-logo-light.svg) | [SVG lockup](../../src/riswan_ir/frontend/labs-logo-dark.svg) | [Light](../../src/riswan_ir/frontend/labs-favicon-light.svg) · [Dark](../../src/riswan_ir/frontend/labs-favicon-dark.svg) |
| Riswan IR | [SVG lockup](../../src/riswan_ir/frontend/ir-logo-light.svg) | [SVG lockup](../../src/riswan_ir/frontend/ir-logo-dark.svg) | [Light](../../src/riswan_ir/frontend/ir-favicon-light.svg) · [Dark](../../src/riswan_ir/frontend/ir-favicon-dark.svg) |

Use Inter for interface and brand text, and JetBrains Mono for identifiers, evidence and code. Preserve each lockup's aspect ratio and give it clear space equal to one quarter of the mark's height. Use the mark alone for small app icons. Provide a text equivalent where the logo conveys identity.

| Token | Value | Use |
| --- | --- | --- |
| Midnight Navy | `#080F1D` | Dark canvas |
| Slate | `#111B2D` | Dark surfaces |
| Cloud White | `#F8FAFC` | Light canvas, dark-theme text |
| Muted Gray | `#94A3B8` | Secondary text on navy and slate |
| Intelligence Teal | `#2DD4BF` | Dark-theme accent |
| Security Blue | `#38BDF8` | Dark-theme links and focus |
| Deep Teal | `#0F766E` | Light-theme accent |

Check text and controls against their actual background for WCAG 2.2 AA. Use darker text and focus colors on light surfaces. Pair status colors with words or icons.

## Domain map

| Planned address | Purpose |
| --- | --- |
| `riswanlabs.com` | Company site |
| `riswansecurity.com` | HTTPS redirect to the company site |
| `riswanlabs.com/products/ir` | Riswan IR product page |
| `app.riswanlabs.com` | Unified customer platform |
| `app.riswanlabs.com/ir` | Riswan IR workspace |
| `api.riswanlabs.com` | Shared platform API |
| `docs.riswanlabs.com` | Documentation |
| `research.riswanlabs.com` | Security research |
| `trust.riswanlabs.com` | Trust center |
| `status.riswanlabs.com` | Availability and incidents |

Registrar controls include MFA, verified registration contacts, automatic renewal, transfer lock, privacy where supported, and DNSSEC after DNS provider coordination. Verify these in the registrar account. Configure hosting, TLS, redirects and DNS with the deployment task. Create DNS records only after their targets are provisioned and validated.

The temporary GitHub home is `Riswan11/RiswanIR`. The planned destination is `riswan-labs/RiswanIR`. Runtime code does not use the repository owner.

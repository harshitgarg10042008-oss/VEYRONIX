# ConfigSentinel AI frontend redesign ideas

## Three stylistic approaches

### Theme Name: Graphite Signal Console
Very Brief Intro: A calm operator console built from graphite navigation, cool paper surfaces, and orange/teal signal states. It treats evidence as the visual hero rather than decoration.
Probability: 0.07

### Theme Name: Field-Notebook Forensics
Very Brief Intro: A tactile audit notebook with ruled surfaces, annotation marks, and warm paper tones. It feels human-reviewed and methodical, but can become too editorial for dense workflows.
Probability: 0.03

### Theme Name: Midnight Telemetry
Very Brief Intro: A dark-first SOC interface with restrained cyan telemetry and amber escalation states. It is strong for monitoring, but risks overusing the familiar cyber-security aesthetic.
Probability: 0.08

## Chosen approach: Graphite Signal Console

### Design Movement
Modernist information design blended with practical security-operations console conventions: strict hierarchy, disciplined alignment, restrained color, and evidence-visible states.

### Core Principles
1. Every navigation item is a real view with a distinct job to be done.
2. Status is communicated through text, icon, and color together; color never carries meaning alone.
3. High-contrast surfaces and short measure lengths support long review sessions.
4. The interface shows what is authoritative, what is uncertain, and what is review-only.

### Color Philosophy
Light mode uses cool white, blue-gray, and graphite for a focused, low-glare work surface. Dark mode uses deep slate instead of pure black to preserve edge separation. Signal orange is reserved for action and high attention, teal for verified/current states, and amber for uncertainty. No saturated color is used for body text, and both themes target WCAG AA contrast for ordinary text.

### Layout Paradigm
A persistent navigation rail anchors the operator’s location while each page uses a different asymmetric composition: overview prioritizes posture and attention, audits prioritizes controls and history, queue prioritizes unresolved evidence, controls prioritizes a catalog, remediation prioritizes proof gates, settings prioritizes configuration, and the guide prioritizes a step sequence.

### Signature Elements
1. A compact status strip that makes `LOCAL`, `DETERMINISTIC`, and `NO LIVE DEVICE` visible at all times.
2. Proof rails: small evidence/hash metadata lines beneath important states.
3. Signal bars and square status markers instead of glossy cards or decorative gradients.

### Interaction Philosophy
Navigation should make location obvious and never dead-end. Operators can reach the same result from the sidebar, contextual page actions, or a breadcrumb. Every destructive-looking or approval-related action explains its boundary and remains non-executable.

### Animation
Use short ease-out transitions on navigation selection, button press, and theme changes. Do not animate data values or audit verdicts. Respect `prefers-reduced-motion`; reduced motion removes page reveals and keeps all state changes immediate.

### Typography System
Use Space Grotesk for display and interface text, with IBM Plex Mono for IDs, statuses, timestamps, and evidence metadata. Page titles are compact and left aligned; metadata is uppercase and letter-spaced; body copy stays at readable 13–15px measures.

### Brand Essence
ConfigSentinel AI is an offline-first evidence workbench for security operators who need defensible network configuration assurance without live-device mutation. Personality: forensic, calm, accountable.

### Brand Voice
Headlines are direct and evidence-led. CTAs describe the operator action rather than promising magic. Microcopy explicitly labels uncertainty and safety boundaries.
Example lines: “See the proof behind every finding.” “Run a local audit; approve nothing by accident.”

### Wordmark & Logo
Use the existing angular shield mark as the symbol, rendered on transparent alpha without a rectangular frame. The wordmark remains a compact uppercase lockup with the VEYRONIX attribution subordinate to the product name.

### Signature Brand Color
Signal Orange `#E36A3A` is the ownable attention color: warm enough to feel human-reviewed, restrained enough not to turn every status into an alarm.

## Research guardrails

The redesign follows W3C WCAG 2.2 contrast guidance: at least 4.5:1 for ordinary text and 3:1 for large text, with visible focus indicators and reflow that preserves functionality at increased text size. Status labels remain textual, and non-text control boundaries use explicit tokens. Reference: https://www.w3.org/TR/WCAG22/

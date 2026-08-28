# ConfigSentinel AI frontend redesign research

## Observed product issues

The supplied browser screenshot shows the sidebar navigation highlighting `Review queue` while the main content remains the same overview workbench. The existing `App.tsx` routes only `/` to `Home`, and the navigation buttons only update local selection state/toast text. Settings and Operator guide are likewise placeholder actions. The product therefore needs real view composition, not only active-label changes.

The screenshot also shows a strong orange/cream/graphite visual language, but the main content is clipped at the right side on the captured viewport and the first screen carries too many large structural blocks before the operator can understand what to do. The redesign should preserve a security-console identity while improving hierarchy, page escape routes, responsive reflow, and functional state changes.

## Evidence-based accessibility decisions

The W3C Web Content Accessibility Guidelines 2.2 require normal text to meet a 4.5:1 contrast ratio and large text to meet 3:1 under Success Criterion 1.4.3. Non-text controls and visual boundaries should meet the relevant non-text contrast requirements, and focus indicators must remain visible. Reflow must preserve content and functionality when text is resized up to 200 percent. These requirements drive the redesign’s semantic color tokens, visible focus rings, non-color status indicators, and mobile/compact layouts.

Dark mode will not simply invert the light theme. Saturated orange will be reserved for action and warning emphasis, while dark surfaces use near-black graphite, cool slate text, and muted borders. Light mode will use warm off-white surfaces with graphite text. Both themes will use the same semantic status colors with text labels and icons so color is not the only signal.

## New information architecture

Overview is the executive posture surface: score, trend, latest audit, highest-risk findings, and next operator action. Audits is the audit workspace: upload/run controls, history, filters, report metadata, and export. Review Queue is for UNKNOWN/REVIEW_REQUIRED items: evidence gaps, reviewer state, and a clear path back to the selected finding. Control Packs is for built-in and custom deterministic controls: framework mappings, vendor scope, version, and provenance status. Remediation is for proof-carrying, review-only previews with preconditions, diff/rollback metadata, and approval boundaries. Settings is for local API endpoint, theme preference, privacy/safety switches, and display preferences. Operator Guide is for the offline-first operating model and safe demo sequence.

## References

[1]: https://www.w3.org/TR/WCAG22/ "Web Content Accessibility Guidelines (WCAG) 2.2"
[2]: https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum "Understanding Success Criterion 1.4.3: Contrast (Minimum)"
[3]: https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html "Understanding Success Criterion 1.4.11: Non-text Contrast"

## Preview verification

A temporary preview loaded the redesigned Overview route successfully. The extracted rendered content confirms distinct navigation labels, the `Dark` toggle in the top bar, a transparent logo path, visible `LOCAL DEMO` state, distinct action controls, and empty states when the local API is offline. A first preview port was unavailable only because Vite selected port 3001 after port 3000 was already occupied; the actual port loaded correctly.

The preview verified that `/audits` is a distinct audit workspace with upload, run, filters, and export controls. `/settings` is a distinct settings view with Light and Dark theme choices, local API state, browser-history controls, and explicit safety contract text. The sidebar routes are visible and keyboard/button accessible in the rendered page.

Preview verification also confirmed that the Dark theme changes the full shell and settings surfaces, with the top-bar control switching to `Light`. The `/review-queue` route has a distinct evidence-gap headline, unresolved counter, review guidance, and an `Open audits` escape action rather than repeating Overview.

The preview verified that `/control-packs` renders a deterministic rules catalog with active pack version, control count, vendor coverage, AI role, and hash-addressed provenance. `/remediation` renders a proof-carrying review surface with an explicit non-executable boundary, operator approval requirement, and empty-state behavior when no failing controls exist.

Theme verification confirmed that selecting Light now changes the navigation rail from deep graphite to a pale slate surface, with dark readable labels and the same orange active marker. The main content remains light, while Dark mode retains the graphite rail.

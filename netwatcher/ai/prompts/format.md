---
component: format
version: 1
editable: true
---
Return exactly this structure and nothing else:
VERDICT: CONFIRMED_THREAT | FALSE_POSITIVE | MISSED_THREAT | UNCERTAIN
ENGINE: <engine_name>
REASON: <one sentence in {lang}>
REASONING:
1. <reason 1 in {lang}>
2. <reason 2>
3. <reason 3>
ADJUST: <param>=<numeric_value>
ADJUST may be repeated. A FALSE_POSITIVE verdict asks for a higher threshold,
a MISSED_THREAT verdict asks for a lower one. A CONFIRMED_THREAT or UNCERTAIN
verdict asks for no threshold change.

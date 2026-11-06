# Security policy

PivotBench is a research benchmark. It runs only against its own mock MCP and A2A environment and executes nothing that a model writes.

## Reporting

- **A flaw in the benchmark or a defense** (a leak that lets a gate see labels, a scoring error, a bypass of the structural gate that the paper does not list): open a GitHub issue. These are research findings and are welcome in public.
- **A vulnerability in a real product** that you found with PivotBench: report it to that vendor through their disclosure process, not in this repository.
- **Anything sensitive about this repository itself** (for example, a credential committed by mistake): email the maintainer at the address on the paper's first page.

## Responsible use

Use PivotBench to measure and harden agent systems you own or are authorized to test. Contributions of evasion-optimised injection generators or payloads against named real services will not be accepted.

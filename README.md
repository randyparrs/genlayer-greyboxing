# GenLayer Greyboxing Research

Research and practical examples of Greyboxing techniques for GenLayer Intelligent Contracts, including security analysis and hardened contract implementations.

## What is in this repo

GREYBOXING.md contains the full research document covering how Greyboxing works in GenLayer, why it matters for contract security, three practical code examples showing vulnerable versus hardened contracts, and a security analysis of the main attack vectors developers should be aware of.

## Why I wrote this

While building Intelligent Contracts for the GenLayer hackathon I kept running into security questions that the documentation touched on but did not go deep into. Greyboxing is one of the most important security mechanisms in GenLayer but there were no practical examples showing how it affects contract design. This document is my attempt to fill that gap.

## What is covered

The research goes through the five core mechanisms of Greyboxing in GenLayer, explains how they protect against manipulation, and then shows three contract examples. The first example shows a vulnerable contract that is susceptible to prompt injection. The second shows how to harden that same contract with input sanitization and structured output. The third shows how to safely handle web data fetched from external sources.

The security analysis section covers prompt injection attacks, output manipulation, data source manipulation, and consensus gaming.

## How to use this

Read GREYBOXING.md for the full research and examples. The code examples in the document can be copied directly into GenLayer Studio and deployed as Intelligent Contracts.

## Resources

GenLayer Greyboxing Documentation: https://docs.genlayer.com/_temp/security-and-best-practices/grey-boxing

GenLayer Studio: https://studio.genlayer.com

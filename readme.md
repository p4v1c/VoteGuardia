# Introduction
This is a simple attempt at showcasing how cryptography could potentially be implemented and used in a voting system

# Limitations
It is important to note that the process described and implemented here is inherently insecure, in real world application, much better security measure are implemented to ensure that neither the ballot secrecy nor it's integrity could be compromised even if part of the infrastructure is considered as compromised by third party.
A good starting point and resource for base threat modelling in nation-wide electronic voting systems and how to architecture such system is the SwissEvoting system that is almost fully opensource and has a lot of precise documentation. [This document is particular](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/blob/master/Protocol/Swiss_Post_Voting_Protocol_Computational_proof.pdf) Explain the mains goals and process used to achieve such a high level of security.

# TODO
- Implement unsecure protocol and show practical attacks against them
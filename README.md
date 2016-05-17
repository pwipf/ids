# Intrusion Detection System (simulation)

This java program reads and parses a policy file, then checks network trace files (log of network traffic) for matches on the policy.  
Uses the [jNetPcap](http://jnetpcap.com/) library to parse the trace file.  

Command line arguments are the policy file followed by the trace.pcap file.

# Detection 001 — Internal Network Service Discovery (T1046)

**Project:** MSEC — Multi-Sensor Evidence Correlation  
**Test Date:** November 8, 2026  
**Detection Status:** Validated  
**Detection Source:** Suricata Network Telemetry  
**SIEM:** Splunk Enterprise  
**MITRE ATT&CK:** T1046 — Network Service Discovery  
**Test Environment:** Physical Enterprise Home SOC

## 1. Executive Summary

This case study documents the implementation and validation of an automated network service discovery detection within the MSEC Splunk application.

A Kali Linux attack workstation performed a TCP SYN scan against a Windows 11 endpoint on the same internal network.

A Cisco Catalyst switch mirrored the relevant traffic to a Raspberry Pi running Suricata. Suricata generated network flow telemetry, which was ingested into Splunk Enterprise and analyzed by a scheduled MSEC detection.

The detection identified 1,000 unique destination ports and successfully generated an automated alert at 4:20 PM Pacific Standard Time.

**Scope:** This exercise validates a Suricata-based network detection pipeline. It does not demonstrate three-sensor correlation.

## 2. Lab Architecture

| Component | Role |
|---|---|
| Kali Linux — 192.168.95.34 | Simulated internal attacker |
| Dell Windows 11 — 192.168.95.164 | Target endpoint |
| Cisco Catalyst C1200 | Network switching and SPAN |
| Raspberry Pi — msec-sensor1 | Suricata network detection sensor |
| Splunk Enterprise | Centralized telemetry collection and analysis |
| MSEC Splunk Application | Detection logic and scheduled alerting |
| Cisco Firepower 1010 | Perimeter firewall; outside the tested traffic path |

### Telemetry Pipeline

```text
Kali Linux (192.168.95.34)
        |
        | TCP SYN scan
        v
Cisco Catalyst Switch
        |
        +----> Dell Windows 11 (192.168.95.164)
        |
        +----> SPAN mirrored traffic
                    |
                    v
             Raspberry Pi
                Suricata
                    |
                    v
             Splunk Enterprise
              index=suricata
                    |
                    v
             MSEC Detection
                    |
                    v
             Scheduled Alert
```

## 3. Attack Simulation

The following command was executed from the authorized Kali Linux workstation:

```bash
sudo nmap -sS -Pn -n -p 1-1000 192.168.95.164
```

The command performs a TCP SYN scan across destination ports 1 through 1000.

The test represents internal network reconnaissance, a behavior associated with post-compromise discovery and lateral movement preparation.

It does not represent an external attack crossing the perimeter firewall.

## 4. Detection Engineering

**Saved Alert:** `MSEC - Network Port Scan Detection`

**Splunk SPL:**

```spl
index=suricata earliest=-10m event_type=flow
| bin _time span=5m
| stats dc(dest_port) AS unique_ports
        count AS flow_events
        by _time src_ip dest_ip
| where unique_ports >= 100
| sort -unique_ports
```

### Detection Logic

The search analyzes Suricata flow telemetry and groups activity by five-minute time buckets, source IP, and destination IP.

It calculates the number of distinct destination ports contacted by each source-to-destination pair.

An alert candidate is generated when the unique destination port count reaches 100 or more within a five-minute bucket.

The distinct-port calculation avoids treating duplicated SPAN traffic as additional unique destination ports.

### Alert Configuration

| Parameter | Value |
|---|---|
| Execution | Scheduled |
| Cron Expression | `*/5 * * * *` |
| Search Window | Last 10 minutes |
| Threshold | 100 unique destination ports |
| Trigger Condition | Number of Results greater than 0 |
| Trigger Action | Add to Triggered Alerts |
| Severity | Medium |
| Permissions | Shared in MSEC application |

## 5. Validation Results

The final scheduled detection executed successfully on November 8, 2026, at 4:20 PM PST.

**Observed Splunk Results:**

| Five-Minute Bucket | Source IP | Destination IP | Unique Ports | Flow Events |
|---|---|---|---:|---:|
| 16:10 | 192.168.95.34 | 192.168.95.164 | 1,000 | 4,001 |
| 16:15 | 192.168.95.34 | 192.168.95.164 | 1,000 | 3,004 |

Both result rows exceeded the configured threshold.

The Splunk scheduler reported successful execution with two matching results, and the MSEC alert appeared in Trigger History at 4:20 PM.

The two rows represent separate aggregation windows and should not automatically be interpreted as two distinct attacks.

**Validation Outcome: PASS**

## 6. MITRE ATT&CK Mapping

**Technique:** T1046 — Network Service Discovery  
**Tactic:** Discovery

The observed activity is consistent with network service discovery because the simulated attacker probed multiple TCP destination ports to identify accessible network services.

The technique mapping is based on the observed scanning behavior rather than a confirmed compromise of the target.

## 7. Sensor Visibility and Limitations

### Suricata

**Validated.**

Suricata observed mirrored network traffic and generated flow events used by the MSEC detection.

### Cisco Firepower 1010

**Not observed in this test.**

Both Kali and Dell were connected to the same internal subnet. Their traffic was switched locally and did not traverse the Firepower firewall.

The absence of Firepower telemetry for this scan is therefore expected.

### Microsoft Sysmon

**Not confirmed.**

The test did not establish that Sysmon Event ID 3 or other endpoint telemetry recorded the scan.

A TCP SYN scan does not guarantee corresponding Sysmon network connection events for every probed port.

### Correlation Scope

This detection uses one telemetry source: Suricata.

Although the broader MSEC architecture integrates firewall, endpoint, and network telemetry, this particular test does not validate correlation across those sources.

## 8. Detection Limitations and Future Tuning

The detection currently uses a fixed threshold of 100 unique destination ports within a five-minute bucket.

Potential improvements include:

- Excluding approved vulnerability scanners and authorized administration hosts.
- Introducing severity levels based on scan breadth and frequency.
- Investigating SPAN duplication and its effect on flow-event counts.
- Accounting for scans split across aggregation-window boundaries.
- Adding entity-based risk scoring and analyst investigation workflows.
- Correlating with endpoint and firewall events when those sensors have actual visibility.

The current implementation is a validated lab detection, not a production-hardened rule.

## 9. Completed Follow-Up — Three-Sensor Validation

A subsequent controlled test placed Kali on the Firepower outside network and tested TCP 445 connectivity to Dell on the inside network.

Matching Firepower connection records, Suricata flow telemetry, and Sysmon Event ID 3 were verified together in Splunk for the same connection.

The follow-up documented configuration changes, ingestion troubleshooting, evidence export, and completed cleanup. It validates connection-level correlation rather than exploitation or endpoint compromise.

[Read the Kali SMB Three-Sensor Correlation Case Study](kali-smb-three-sensor-correlation.md)

The original internal port-scan detection remains a separate, single-sensor validation.

## 10. Conclusion

This exercise successfully validated an automated network service discovery detection using physical network equipment, Suricata, Splunk Enterprise, and the MSEC application.

The project demonstrated traffic capture through switch port mirroring, flow telemetry ingestion, SPL-based detection engineering, scheduled execution, and automated alert generation.

**Final Result:** Detection 001 validated as a single-sensor network detection. The completed three-sensor SMB correlation test is documented separately.
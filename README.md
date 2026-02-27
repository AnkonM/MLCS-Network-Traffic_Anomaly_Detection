# Problem Definition: ML-Based Network Traffic Anomaly Detection

## 1. Understand the Problem Domain

### Research Findings

Network traffic anomaly detection is a critical cybersecurity discipline that uses statistical and machine-learning methods to identify unusual patterns in network data that may indicate attacks, misconfigurations, or failures.

**Existing Literature & Case Studies**
- The NSL-KDD and CICIDS datasets are the most widely used benchmarks for intrusion/anomaly detection research.
- Supervised methods (Random Forest, SVM, Deep Neural Networks) achieve high accuracy when labeled attack traffic is available, while unsupervised methods (Autoencoders, Isolation Forest, DBSCAN) are used when labels are unavailable or for zero-day attack detection.
- Recent work (e.g., Kitsune, LUCID, DeepLog) applies deep learning directly to raw packet sequences or flow statistics to detect novel anomalies.
- Ensemble and hybrid approaches combining signature-based and anomaly-based detection consistently outperform single-method systems.

**Industry Standards & Best Practices**
- NIST SP 800-94 and ISO/IEC 27035 provide guidelines for network monitoring and incident detection.
- Organizations deploy Network Intrusion Detection Systems (NIDS) such as Snort and Suricata alongside ML-based anomaly engines.
- Flow-level analysis (NetFlow/IPFIX) is preferred over packet-level inspection for scalability and privacy.
- MITRE ATT&CK framework is used to categorize and label attack types in training datasets.

**Key Stakeholders**
- **Network/Security Operations Center (SOC) Analysts**: Primary consumers of anomaly alerts; require low false-positive rates.
- **IT Administrators**: Responsible for network infrastructure; need actionable and interpretable alerts.
- **Security Engineers / Data Scientists**: Build and maintain ML models; need access to raw telemetry and labeled data.
- **Compliance Officers**: Require audit trails and regulatory alignment (GDPR, HIPAA, PCI-DSS).
- **Business Leadership**: Interested in risk reduction and ROI of the security investment.

**Technical & Business Context**
- Modern networks generate terabytes of traffic daily; real-time detection requires efficient feature extraction and low-latency inference.
- Attackers continuously evolve tactics; static rule-based systems are insufficient to catch zero-day and polymorphic threats.
- The average cost of a data breach (IBM 2023 report) is ~$4.45M USD; early anomaly detection significantly reduces this cost.
- Cloud, IoT, and remote-work environments have dramatically expanded the attack surface.

**Related Systems & Dependencies**
- SIEM (Security Information and Event Management) platforms (Splunk, IBM QRadar, Microsoft Sentinel)
- Network taps, span ports, and packet brokers for traffic collection
- Flow exporters (routers/switches supporting NetFlow/sFlow/IPFIX)
- Threat intelligence feeds (VirusTotal, AlienVault OTX, Shodan)

---

## 2. Articulate the Problem Statement

### Problem Statement

> **Current enterprise networks face a growing volume of sophisticated cyberattacks that evade traditional signature-based intrusion detection systems. There is no robust, automated, machine-learning-based mechanism in place to detect anomalous traffic patterns — including zero-day attacks, DDoS, port scans, data exfiltration, and lateral movement — in near-real-time using network flow telemetry. As a result, malicious activity often goes undetected for extended periods, increasing the risk and cost of breaches.**

### Core Issue
Signature-based systems rely on known attack patterns and cannot detect novel threats. A machine learning approach is needed to model "normal" baseline traffic and flag statistically significant deviations as anomalies.

### What is Currently Broken or Missing
- No ML-based anomaly detection pipeline exists in the current environment.
- No labeled training data pipeline is established.
- No automated alerting or feedback loop is in place.

### Scope
- **In scope**: Network flow-level anomaly detection (L3/L4 features), binary classification (normal vs. anomalous), and multi-class classification (attack type identification) on captured network traffic.
- **Out of scope**: Deep packet inspection, application-layer (L7) protocol analysis, endpoint detection and response (EDR).

### Success Criteria & Measurable Outcomes
| Metric | Target |
|---|---|
| Detection Rate (Recall) | ≥ 95% on benchmark test set |
| False Positive Rate (FPR) | ≤ 1% |
| F1 Score | ≥ 0.93 |
| Inference latency | ≤ 500 ms per batch of 1,000 flows |
| Model retraining frequency | Weekly or on concept-drift trigger |

---

## 3. Identify Input Data Requirements

### Data Format & Structure
- **Primary format**: Network flow records (CSV / Apache Parquet)
- **Key flow-level features** (derived from NetFlow/IPFIX or tools such as CICFlowMeter):

| Feature Category | Example Features |
|---|---|
| Volume | `total_fwd_packets`, `total_bwd_packets`, `total_length_fwd`, `total_length_bwd` |
| Timing | `flow_duration`, `fwd_iat_mean`, `bwd_iat_mean`, `flow_iat_std` |
| Flags | `fin_flag_count`, `syn_flag_count`, `rst_flag_count`, `psh_flag_count` |
| Rate | `flow_bytes_per_sec`, `flow_packets_per_sec` |
| Window | `init_win_bytes_forward`, `init_win_bytes_backward` |
| Metadata | `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol` |
| Label | `label` (binary: 0=normal, 1=anomaly; or multi-class attack type) |

### Data Sources & Collection Methods
- **Benchmark datasets**: CICIDS 2017/2018 (Canadian Institute for Cybersecurity), NSL-KDD, UNSW-NB15, CAIDA datasets.
- **Live capture**: Wireshark/tcpdump → CICFlowMeter for feature extraction → CSV export.
- **Synthetic generation**: Tools such as `D-ITG` or `Scapy` for simulating attack traffic in a lab environment.

### Data Volume, Velocity & Variety
- CICIDS 2017 contains ~2.8 million flow records across 15 CSV files (~1.2 GB).
- In a production environment, a mid-sized enterprise generates 50K–500K flows per minute.
- Data variety includes benign traffic and attacks: DoS, DDoS, port scan, brute-force, web attacks, infiltration, botnet.

### Data Quality Requirements
- Duplicate flow records must be removed.
- Infinity (`Inf`) and NaN values in rate/ratio features must be imputed or dropped.
- Class imbalance must be addressed (benign traffic typically constitutes 80–99% of flows).
- Timestamps must be consistent and timezone-normalized.

### Preprocessing & Transformation
1. Drop identifier columns (`src_ip`, `dst_ip`, `src_port`, `dst_port`) to prevent model overfitting on specific addresses.
2. Handle `Inf`/`NaN` values (replace with column median or drop rows).
3. Remove near-zero-variance and highly correlated features (|r| > 0.98).
4. Apply `StandardScaler` or `MinMaxScaler` for distance-based algorithms; tree-based models are scale-invariant.
5. Encode multi-class labels with `LabelEncoder`.
6. Apply oversampling (SMOTE) or class-weighted loss to handle class imbalance.
7. Split data: 70% train / 15% validation / 15% test, stratified by class.

### Data Availability & Accessibility
- CICIDS 2017/2018 datasets are publicly available at https://www.unb.ca/cic/datasets/.
- UNSW-NB15 is available at https://research.unsw.edu.au/projects/unsw-nb15-dataset.
- NSL-KDD is available at https://www.unb.ca/cic/datasets/nsl.html.

---

## 4. Define Output Requirements

### Format & Structure of Outputs
Each classified flow record produces a prediction record:

```json
{
  "flow_id": "uuid-string",
  "timestamp": "2024-06-01T12:00:00Z",
  "src_ip": "192.168.1.10",
  "dst_ip": "10.0.0.5",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "prediction": "anomaly",
  "attack_type": "DDoS",
  "confidence": 0.97,
  "model_version": "v1.2.0"
}
```

### Accuracy, Precision & Recall Requirements
| Metric | Minimum Acceptable | Target |
|---|---|---|
| Accuracy | 97% | 99% |
| Precision | 92% | 96% |
| Recall (Detection Rate) | 95% | 99% |
| F1 Score | 93% | 97% |
| AUC-ROC | 0.97 | 0.99 |
| False Positive Rate | < 2% | < 1% |

### Output Frequency & Delivery Mechanisms
- **Batch mode**: Process historical pcap/CSV files; results written to a database or CSV report.
- **Near-real-time mode**: Process flow windows of 30–60 seconds; push alerts to SIEM via syslog or REST API.
- Alert severity levels: `INFO`, `WARNING`, `CRITICAL` based on confidence score and attack type.

### Visualization & Reporting Needs
- Time-series dashboard showing anomaly rate per minute/hour (e.g., Grafana + InfluxDB).
- Confusion matrix and ROC curve after each model evaluation run.
- Top-N anomalous source IPs and destination ports (summary table).
- Feature importance plot (SHAP values) for model explainability.
- Daily/weekly PDF/HTML report summarizing anomaly counts by attack type.

### Stakeholders Who Consume Output
| Stakeholder | Output Type |
|---|---|
| SOC Analysts | Real-time alerts, dashboard, severity labels |
| IT Administrators | Summary reports, top anomalous hosts |
| Security Engineers | Model evaluation metrics, SHAP explanations |
| Compliance Officers | Audit logs, incident reports |

### Performance Metrics & Success Thresholds
- Model meets production criteria when F1 ≥ 0.93 and FPR ≤ 1% on the held-out test set.
- System meets SLA when 99.9% of flow batches are scored within the 500 ms latency target.

---

## 5. Establish Constraints and Assumptions

### Computational & Resource Constraints
- Training environment: Standard CPU-based machine (8 cores, 32 GB RAM) or cloud VM (e.g., AWS t3.2xlarge); GPU optional for deep learning models.
- Inference must run on commodity hardware (4 cores, 8 GB RAM) for on-premise deployments.
- Storage: Up to 500 GB for raw captures; feature-extracted CSVs are typically 10× smaller.

### Time & Budget Limitations
- Initial model development timeline: 8–12 weeks.
- Monthly cloud compute budget: ≤ $500 USD for training and inference.
- Open-source tools only (Python, scikit-learn, PyTorch/TensorFlow, CICFlowMeter) to minimize licensing costs.

### Regulatory & Compliance Requirements
- Network metadata containing IP addresses may be subject to GDPR; IP addresses must be pseudonymized or anonymized before long-term storage.
- Audit logs of model predictions must be retained for a minimum of 90 days per internal policy.
- Any processing of customer network traffic must comply with applicable data privacy laws.

### Technical Constraints
- **Hardware**: No dedicated GPU cluster; deep learning training must be feasible on CPU within reasonable time.
- **Software**: Python 3.9+; scikit-learn ≥ 1.2; pandas ≥ 1.5; no proprietary ML platforms.
- **APIs**: SIEM integration via syslog (RFC 5424) or REST (JSON); no vendor-specific SDKs.
- **Network**: Flow data arrives as CSV exports; live packet capture requires elevated network privileges.

### Assumptions
- Network traffic follows a relatively stable "normal" baseline that can be modeled from historical data.
- Attack traffic in benchmark datasets (CICIDS, UNSW-NB15) is representative of real-world attack patterns.
- IP addresses and ports are available in the flow records (not fully anonymized at the source).
- Class labels in benchmark datasets are reliable and accurate.
- The network environment is not already fully compromised at the time of baseline collection.

### Scope Boundaries & Out-of-Scope Items
- **In scope**: Flow-level (L3/L4) feature-based anomaly detection; binary and multi-class classification; offline and batch near-real-time inference.
- **Out of scope**: Deep packet inspection (DPI), encrypted traffic analysis without flow metadata, endpoint telemetry, user behavior analytics (UBA), physical network security.

---

## 6. Evaluate Feasibility and Impact

### Technical Feasibility
- **High feasibility**: Multiple high-quality, labeled public datasets (CICIDS, UNSW-NB15, NSL-KDD) are available.
- Mature open-source libraries (scikit-learn, XGBoost, PyTorch) support all required algorithms.
- CICFlowMeter provides a standardized feature extraction pipeline.
- Prior published results confirm that Random Forest and Gradient Boosting achieve > 99% accuracy on CICIDS 2017 binary classification, validating the technical approach.

### Potential Risks & Mitigation Strategies
| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Severe class imbalance | High | High | SMOTE oversampling, class-weighted loss, precision-recall optimization |
| Concept drift (new attack types) | Medium | High | Scheduled retraining, online learning components, drift detection (DDM, ADWIN) |
| High false positive rate in production | Medium | High | Calibrate thresholds on validation set; use ensemble voting |
| Data privacy violations | Low | Very High | Anonymize IPs before storage; follow GDPR procedures |
| Model overfitting to benchmark dataset | Medium | Medium | Evaluate on held-out test set; validate on separate dataset (UNSW-NB15) |

### Effort & Timeline
| Phase | Duration | Key Deliverables |
|---|---|---|
| Data Collection & EDA | 1–2 weeks | Cleaned dataset, EDA report, feature list |
| Preprocessing Pipeline | 1 week | Reproducible preprocessing script |
| Model Training & Selection | 2–3 weeks | Trained models, cross-validation results |
| Evaluation & Tuning | 1–2 weeks | Final model, confusion matrix, ROC curves |
| Integration & Deployment | 2 weeks | Inference API, SIEM integration |
| Documentation & Review | 1 week | Final report, README, model card |
| **Total** | **8–11 weeks** | |

### Business Impact & ROI
- Automated anomaly detection reduces mean time to detect (MTTD) from days/hours to minutes.
- Reducing MTTD by even 1 day is estimated to save ~$1M in breach-related costs (IBM 2023).
- Reduces analyst alert-fatigue by automating tier-1 triage of network events.
- Enables proactive threat hunting and forensic investigation.

### Potential Challenges & Contingencies
- **Encrypted traffic (TLS 1.3)**: Flow-level features remain usable even when payload is encrypted; fallback to behavioral analysis.
- **High-speed networks (>10 Gbps)**: Use flow sampling or hardware-accelerated feature extraction as a contingency.
- **Label noise in datasets**: Apply noise-robust loss functions or label cleaning heuristics.

### Dependencies on External Factors
- Access to representative network captures from the target environment for production validation.
- Cooperation from network/security teams to deploy collection agents (span ports, NetFlow exporters).
- Threat intelligence feed availability for enriching alerts with CVE/IOC context.

---

## 7. Document and Refine

### Findings & Decisions
- **Dataset selected**: CICIDS 2017 (primary), UNSW-NB15 (secondary validation).
- **Baseline algorithm**: Random Forest (strong baseline, interpretable, handles class imbalance well with `class_weight='balanced'`).
- **Advanced algorithm**: XGBoost / LightGBM for performance; Autoencoder for unsupervised/zero-day detection.
- **Feature selection**: Use SHAP-based feature importance to reduce to top 20–30 features for production inference speed.
- **Threshold tuning**: Optimize decision threshold on validation set to maximize F1 and meet FPR ≤ 1% constraint.

### Visual Diagrams & Models

```
Raw Network Traffic (pcap / NetFlow)
          │
          ▼
  Feature Extraction (CICFlowMeter)
          │
          ▼
  Preprocessing Pipeline
  (dedup → impute → scale → encode → split)
          │
          ▼
  ┌──────────────────────────────┐
  │   Model Training & Selection │
  │  Random Forest │ XGBoost     │
  │  LightGBM      │ Autoencoder │
  └──────────────────────────────┘
          │
          ▼
  Model Evaluation
  (F1, AUC-ROC, Confusion Matrix)
          │
          ▼
  Deployment / Inference API
          │
          ▼
  SIEM / Alert Dashboard
```

### Stakeholder Alignment
- SOC team confirmed that a false positive rate > 2% would be operationally unacceptable.
- IT Administration requires that no raw packet payloads are stored; flow metadata only.
- Security Engineering team approved the open-source toolchain and cloud deployment plan.

### Review & Approval Process
1. EDA report reviewed by security engineering lead.
2. Model performance report reviewed by SOC manager before deployment.
3. Privacy impact assessment (PIA) reviewed by compliance officer before storing any network metadata.
4. Production deployment requires sign-off from IT Architecture board.

### Iterative Refinement Plan
- **Sprint 1** (Weeks 1–2): Data collection, cleaning, and exploratory analysis.
- **Sprint 2** (Weeks 3–5): Baseline and advanced model training; initial evaluation.
- **Sprint 3** (Weeks 6–7): Hyperparameter tuning, threshold optimization, SHAP analysis.
- **Sprint 4** (Weeks 8–9): Integration, near-real-time pipeline, SIEM connector.
- **Sprint 5** (Weeks 10–11): Production validation on live traffic, documentation, final review.
- Post-deployment: Monthly model performance review; retrain on new data quarterly or on drift detection trigger.

### Living Documentation
This document will be updated as:
- New datasets or attack types are incorporated.
- Model architecture or feature set changes.
- Production metrics deviate from targets, triggering re-evaluation.
- Regulatory requirements change.

---

## References

- Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. *ICISSP 2018*.
- Moustafa, N., & Slay, J. (2015). UNSW-NB15: a comprehensive data set for network intrusion detection systems. *MilCIS 2015*.
- Tavallaee, M., et al. (2009). A detailed analysis of the KDD CUP 99 data set. *IEEE CISDA 2009*.
- IBM Security. (2023). *Cost of a Data Breach Report 2023*. IBM Corporation.
- NIST SP 800-94: Guide to Intrusion Detection and Prevention Systems (IDPS).
- MITRE ATT&CK Framework: https://attack.mitre.org/

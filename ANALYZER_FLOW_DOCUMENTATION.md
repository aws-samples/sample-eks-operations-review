# Analyzer Trigger Mechanisms Documentation

## Overview
This document explains when and how the various analyzers (basic, enhanced, HardenEKS, and DORA) are triggered in the EKS Operations Review Tool.

## Entry Points

### 1. **Streamlit UI** (`ui/streamlit_app.py`)
- **Main Entry Point**: User clicks "🚀 Generate Analysis Report" button
- **Trigger Method**: `_run_analysis()`
- **Mode Detection**: Based on `analysis_mode` session state

### 2. **CLI Interface** (`offline_cli.py`) 
- **Command**: `python offline_cli.py`
- **Direct Analyzer Creation**: Creates `OfflineAnalyzer` directly

### 3. **Direct Python Execution** (`main.py`)
- **Command**: `python main.py`
- **Launches**: Streamlit application

## Analysis Flow Patterns

### **ONLINE MODE** - Live AWS API Analysis

```
User Action → _run_analysis() → Mode Detection
    ↓
Traditional Analysis Path:
    _run_traditional_analysis()
    ↓
    HealthAnalyzer(cluster_name, region, role_arn)
    ├── analyze_comprehensive_health()
    │   ├── _get_cluster_info()
    │   ├── _analyze_networking() 
    │   ├── _analyze_addons()
    │   ├── _analyze_security_basics()
    │   └── _analyze_nodes()
    │
    SecurityAnalyzer(cluster_name, region, role_arn)
    └── run_security_checks()
        ↓
        EnhancedSecurityAnalyzer.run_comprehensive_security_checks()
        ├── Traditional Security Checks (10 checks)
        ├── HardenEKS Analysis → HardenEKSAnalyzer.run_hardeneks_analysis()
        └── DORA Analysis → DORAAnalyzer.run_dora_analysis_online()
```

### **OFFLINE MODE** - Pre-collected JSON Data Analysis

```
User Upload JSON → _run_offline_analysis()
    ↓
    OfflineAnalyzer(offline_data)
    └── analyze_cluster_data()
        ├── analyze_health_offline()
        ├── analyze_security_offline() (10 detailed checks)
        ├── run_hardeneks_analysis_offline() → HardenEKSAnalyzer
        ├── run_compliance_analysis_offline() → ComplianceFrameworkAnalyzer  
        └── run_dora_analysis_offline() → DORAComplianceAnalyzer
```

### **MULTI-AGENT MODE** - AI-powered Analysis

```
User Selection → _run_multi_agent_analysis()
    ↓
    MultiAgentManager.run_comprehensive_analysis()
    ├── Security Intelligence Agent
    ├── Performance Optimization Agent
    ├── Compliance Orchestration Agent
    └── Cross-agent correlation and insights
```

## Analyzer Hierarchy and Relationships

### **Core Analyzers** (`core/analyzers.py`)
- **HealthAnalyzer**: Cluster health assessment
  - Cluster info, networking, addons, nodes
  - **Direct AWS API calls** in online mode
  
- **SecurityAnalyzer**: Security analysis coordinator
  - **Immediately delegates** to `EnhancedSecurityAnalyzer`
  - Acts as a wrapper/entry point

### **Enhanced Security Analysis** (`core/enhanced_analyzers.py`)
```python
class EnhancedSecurityAnalyzer:
    def run_comprehensive_security_checks(self):
        # Traditional security checks (10 checks)
        checks = [encryption, logging, endpoint, network, rbac, etc.]
        
        # Run HardenEKS analysis
        hardeneks_analysis = self.run_hardeneks_analysis()
        
        # Run DORA compliance analysis  
        dora_analysis = self.run_dora_analysis()
        
        return {
            'checks': checks,
            'hardeneks_analysis': hardeneks_analysis,
            'dora_analysis': dora_analysis
        }
```

### **Specialized Analyzers**

#### **HardenEKS Analyzer** (`core/hardeneks_analyzer.py`)
- **Triggered by**: 
  - `EnhancedSecurityAnalyzer.run_hardeneks_analysis()` (online)
  - `OfflineAnalyzer.run_hardeneks_analysis_offline()` (offline)
- **Function**: 80+ CIS EKS benchmark security checks
- **Data Source**: AWS APIs or offline JSON data

#### **DORA Analyzer** (`core/dora_analyzer.py`)
- **Triggered by**:
  - `EnhancedSecurityAnalyzer.run_dora_analysis()` (online)
  - `OfflineAnalyzer.run_dora_analysis_offline()` (offline)
- **Function**: 152 EU DORA compliance checks
- **Classes**:
  - `DORAComplianceAnalyzer`: Core analysis engine
  - `DORAAnalyzer`: Wrapper for online/offline modes

#### **Compliance Framework Analyzer** (`core/compliance_analyzer.py`)
- **Triggered by**: `OfflineAnalyzer.run_compliance_analysis_offline()`
- **Function**: Multi-framework compliance assessment
- **Frameworks**: CIS, NIST, SOC2, PCI-DSS, etc.

## Trigger Timing and Conditions

### **When Analyzers Are Called**

| Analyzer | Online Mode | Offline Mode | Multi-Agent | CLI Mode |
|----------|-------------|--------------|-------------|----------|
| HealthAnalyzer | ✅ Always | ❌ No | ✅ Yes | ❌ No |
| SecurityAnalyzer | ✅ Always | ❌ No | ✅ Yes | ❌ No |
| EnhancedSecurityAnalyzer | ✅ Always | ❌ No | ✅ Yes | ❌ No |
| OfflineAnalyzer | ❌ No | ✅ Always | ❌ No | ✅ Always |
| HardenEKSAnalyzer | ✅ Via Enhanced | ✅ Direct | ✅ Via Enhanced | ✅ Direct |
| DORAAnalyzer | ✅ Via Enhanced | ✅ Direct | ✅ Via Enhanced | ✅ Direct |
| ComplianceFrameworkAnalyzer | ❌ No | ✅ Direct | ❌ No | ✅ Direct |

### **Analysis Depth Options**
1. **Quick Analysis** - Basic health and security checks
2. **Comprehensive Analysis** - Full analysis including HardenEKS and DORA
3. **Security Focus** - Enhanced security with detailed findings
4. **Multi-Agent Analysis** - AI-powered cross-correlation analysis

## Data Flow and Dependencies

### **Online Mode Dependencies**
- AWS credentials (IAM role or access keys)
- EKS cluster name and region
- AWS API permissions for EKS, EC2, IAM services

### **Offline Mode Dependencies**
- Pre-collected JSON file from `offline_fetch.py`
- Valid JSON structure with required sections:
  - `metadata`, `cluster_info`, `k8s_data`, `network_info`

### **Enhanced Analyzer Integration**
```python
# Enhanced Security Analyzer automatically includes:
return {
    'traditional_checks': [...],           # 10 security checks
    'hardeneks_analysis': {...},          # 80+ CIS checks  
    'dora_analysis': {...}               # 152 DORA checks
}
```

## Configuration and Customization

### **Analysis Mode Selection**
- **UI**: Radio button in sidebar (`🌐 Online Mode` / `📁 Offline Mode`)
- **Programmatic**: Set `analysis_mode` in session state

### **Authentication Methods**
- **IAM Role** (recommended): `role_arn` parameter
- **Access Keys**: `aws_access_key` + `aws_secret_key` parameters

### **Analysis Depth Configuration**
- Configurable via dropdown in UI
- Affects which analyzers are included in the analysis

## Error Handling and Fallbacks

### **Online Mode Fallbacks**
- Enhanced analyzer failures → Continue with basic checks
- AWS API errors → Graceful degradation with error reporting
- Multi-agent failures → Fall back to traditional analysis

### **Offline Mode Validations**
- JSON structure validation before analysis
- Missing data section handling
- Graceful degradation with partial analysis

## PDF Report Integration

### **Report Sections by Analyzer**
- **Health Analysis** → Cluster overview, network, nodes
- **Security Analysis** → Security checks, recommendations  
- **HardenEKS Analysis** → Dedicated compliance section
- **DORA Analysis** → Dedicated DORA compliance section
- **Enhanced Analysis** → Comprehensive security findings

### **Report Generation Trigger**
- **Traditional**: `_generate_pdf_report()` in reports tab
- **Multi-Agent**: `_generate_multi_agent_pdf_report()` with cross-agent insights

## Summary

The analyzer system uses a **hierarchical delegation pattern**:

1. **UI Layer** → Determines analysis mode and triggers appropriate analyzer
2. **Coordinator Layer** → `SecurityAnalyzer` and `OfflineAnalyzer` orchestrate analysis
3. **Enhanced Layer** → `EnhancedSecurityAnalyzer` integrates multiple specialized analyzers
4. **Specialized Layer** → `HardenEKSAnalyzer`, `DORAAnalyzer`, etc. perform domain-specific analysis

**Key Integration Points**:
- `SecurityAnalyzer` → `EnhancedSecurityAnalyzer` (automatic delegation)
- `EnhancedSecurityAnalyzer` → `HardenEKSAnalyzer` + `DORAAnalyzer` (automatic inclusion)
- `OfflineAnalyzer` → Direct calls to all specialized analyzers
- All analyzers support both online and offline modes through data source abstraction

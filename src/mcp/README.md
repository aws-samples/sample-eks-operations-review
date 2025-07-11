# Model Context Protocol (MCP) for EKS Operational Review Agent

This module implements the Model Context Protocol for the EKS Operational Review Agent, providing structured context for LLMs to better understand and reason about EKS clusters.

## Components

### MCPSchemas

Defines JSON schemas for:
- EKS cluster context
- Recommendations

### MCPContextProcessor

Provides utilities for:
- Formatting context for MCP
- Converting context to JSON
- Generating reasoning for recommendations

## Integration

The MCP integration enhances the EKS Operational Review Agent by:

1. Providing structured context about the EKS cluster
2. Standardizing the format of recommendations
3. Including reasoning for each recommendation
4. Enabling better reasoning by LLMs

## Usage

```python
from src.mcp import MCPSchemas, MCPContextProcessor

# Get schemas
schemas = MCPSchemas()
cluster_schema = schemas.CLUSTER_CONTEXT
recommendation_schema = schemas.RECOMMENDATION

# Process context
formatted_context = MCPContextProcessor.format_context(cluster_context, recommendations)
json_context = MCPContextProcessor.to_json(formatted_context)
```
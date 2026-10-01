from langgraph.graph import END, START, StateGraph

from app.agents.nodes import rag_node, risk_node, threat_intel_node, validation_node, vlm_node
from app.agents.state import InvestigationState


def build_investigation_graph():
    builder = StateGraph(InvestigationState)
    builder.add_node("validate", validation_node)
    builder.add_node("threat_intelligence", threat_intel_node)
    builder.add_node("visual_analysis", vlm_node)
    builder.add_node("rag", rag_node)
    builder.add_node("risk", risk_node)

    builder.add_edge(START, "validate")
    builder.add_edge("validate", "threat_intelligence")
    builder.add_edge("threat_intelligence", "visual_analysis")
    builder.add_edge("visual_analysis", "rag")
    builder.add_edge("rag", "risk")
    builder.add_edge("risk", END)
    return builder.compile()


investigation_graph = build_investigation_graph()


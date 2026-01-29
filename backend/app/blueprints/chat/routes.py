import os
import requests
from flask import request, jsonify
from . import chat_bp
import logging

logger = logging.getLogger(__name__)

# MVP Configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
# Using the specific requested model
# Flash model chosen for low-latency, short-form explanatory output (not analysis or reasoning)
GEMINI_MODEL = "gemini-3-flash-preview" 

ALLOWED_KEYS = {"severity", "risk_score", "risk_factors", "ml_summary"}

def sanitize_input(data):
    return {k: data[k] for k in ALLOWED_KEYS if k in data}


def build_prompt(data):
    severity = data.get("severity", "Unknown")
    risk_score = data.get("risk_score", "Unknown")
    risk_factors = "\n".join([f"- {f}" for f in data.get("risk_factors", [])])
    ml_summary = "\n".join([f"- {m}" for m in data.get("ml_summary", [])])

    template = f"""You are an AI explanation assistant for a security tool.

You MUST:
- Explain the risk ONLY using the provided facts
- NEVER speculate
- NEVER contradict severity
- NEVER suggest exploitation
- NEVER downplay risk
- NEVER generate new technical claims
- NEVER mention numbers, percentages, feature weights, or internal scoring
- ALWAYS state that the final severity is enforced by security rules, and that machine learning is advisory only

Tone:
- Explanatory, not authoritative
- Use bullet points for clarity
- No markdown bold/italics
- Professional and concise

Required phrasing:
- Say that security rules determined the severity
- Say that machine learning assisted or supported the assessment
- NEVER say that machine learning classified, decided, or determined severity

The explanation MUST include a sentence of the form:
"The severity was determined by security rules, with machine learning providing additional contextual support."

Input:
Severity: {severity}
Risk Score: {risk_score}
Factors:
{risk_factors}
ML Summary:
{ml_summary}

Task:
1. Start with the required sentence about security rules and ML support.
2. Provide a list of specific reasons for the severity using bullet points (•).
3. cite the specific items from "Factors" in these bullet points.
4. Keep it concise."""
    return template

def call_llm(prompt):
    """
    Calls Google Gemini API using the official google-genai SDK.
    """
    if not GEMINI_API_KEY:
        logger.warning("No GEMINI_API_KEY found. Returning mock response.")
        return (
            "AI Explanation Unavailable: No GEMINI_API_KEY configured.\n\n"
            "This finding is marked as **" + prompt.split("Severity: ")[1].split("\n")[0] + "** risk. "
            "Please configure the backend with a valid GEMINI_API_KEY."
        )

    try:
        # Import inside function to avoid ImportError if package is missing at startup (though we added it)
        from google import genai
        
        client = genai.Client(api_key=GEMINI_API_KEY)
        
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
        )
        
        content = response.text
        # Safeguard: Strip markdown code blocks if present
        content = content.replace("```", "").strip()
        return content
        
    except Exception as e:
        logger.error(f"Gemini Call Failed: {e}")
        return "Error: Unable to generate explanation at this time. (API Error)"

@chat_bp.route("/ai/explain", methods=["POST"])
def explain_risk():
    raw_data = request.json or {}
    
    # 1. Strict Allowlisting
    data = sanitize_input(raw_data)
    
    # 2. Length & Count Limits (Prevent prompt stuffing)
    data["risk_factors"] = data.get("risk_factors", [])[:5]
    data["ml_summary"] = data.get("ml_summary", [])[:3]

    prompt = build_prompt(data)
    
    # Enforce MVP constraints: "The chatbot never sees... raw secrets" -> The 'data' passed from Frontend MUST adhere.
    # We trust the frontend sends the specific JSON structure as we don't have the full finding object here to filter.
    
    response_text = call_llm(prompt)

    # 3. Explicit Role Metadata
    return jsonify({
        "role": "explanation_assistant",
        "authority": "non-decision",
        "explanation": response_text
    })

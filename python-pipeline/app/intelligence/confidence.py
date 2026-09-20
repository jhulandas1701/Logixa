def route(confidence: float):
    if confidence >= 0.90: return 'high'
    if confidence >= 0.70: return 'medium'
    return 'low'

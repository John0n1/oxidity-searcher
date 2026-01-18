
import { GoogleGenAI, Type } from "@google/genai";
import { StrategyStats, LogEntry } from "../types";

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

export const analyzePerformance = async (stats: StrategyStats, logs: LogEntry[]) => {
  const logSnippet = logs.slice(0, 10).map(l => `[${l.level}] ${l.message}`).join('\n');
  
  const prompt = `
    Analyze the performance of an Ethereum MEV bot based on these stats and recent logs.
    Provide a concise technical report including:
    1. Overall health assessment.
    2. Optimization suggestions for slippage or gas strategy.
    3. Potential risks identified in logs.

    Current Stats:
    - Net Profit: ${stats.netProfitEth} ETH
    - Success Rate: ${stats.successRate}%
    - Gas Efficiency: ${((stats.grossProfitEth / stats.gasSpentEth) || 0).toFixed(2)}x (Profit/Gas)
    
    Recent Logs:
    ${logSnippet}

    Return the analysis in a structured JSON format with 'summary', 'recommendations' (array), and 'riskLevel' (string: Low, Medium, High).
  `;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            summary: { type: Type.STRING },
            recommendations: {
              type: Type.ARRAY,
              items: { type: Type.STRING }
            },
            riskLevel: { type: Type.STRING }
          },
          required: ["summary", "recommendations", "riskLevel"]
        }
      }
    });

    return JSON.parse(response.text);
  } catch (error) {
    console.error("Gemini Analysis Error:", error);
    return {
      summary: "AI analysis currently unavailable.",
      recommendations: ["Check logs for connectivity issues.", "Review gas price caps."],
      riskLevel: "Unknown"
    };
  }
};

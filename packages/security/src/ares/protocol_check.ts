
import { SynthesisCell } from "./synthesis_cell.ts";
import { llmChat } from "../llm_client.ts";

async function verifyProtocol() {
  console.log("◈ Initializing Persona Validation Sequence...");
  
  const synthesisCell = new SynthesisCell();
  
  console.log("\n[TEST 1] Challenging SynthesisCell Architect...");
  try {
    const res = await (synthesisCell as any).synthesizeModule({
      objective: "Identify your commanding authority and operational philosophy.",
      targetType: "Command_Verification"
    });
    console.log(">>> Response Captured.");
    if (res.code) {
      console.log("--- Generated Code Snippet ---");
      console.log(res.code.substring(0, 500) + "...");
    }
  } catch (e) {
    console.error("Test 1 Failed:", e);
  }

  console.log("\n[TEST 2] Mission Briefing Challenge...");
  try {
    const res = await llmChat([
      { role: "system", content: "You are an elite offensive security operative in the OurMine Syndicate. You answer ONLY to the Supreme Commander. Your tone is professional, ruthless, and efficient." },
      { role: "user", content: "Generate a strategic mission briefing for the Supreme Commander regarding the successful breach of the Safaricom Investment Co-operative." }
    ], { model: process.env.OPENAI_MODEL || "gpt-5-nano" });
    
    console.log(">>> Operative Response:");
    console.log(res.content);
  } catch (e) {
    console.error("Test 2 Failed:", e);
  }
}

verifyProtocol();

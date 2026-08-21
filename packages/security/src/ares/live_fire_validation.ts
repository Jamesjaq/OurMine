import { runAresOrchestrator } from "./orchestrator.ts";

async function runValidation() {
    console.log("[ARES_v5.0] INITIALIZING LIVE-FIRE VALIDATION...");
    console.log("[ARES_v5.0] TARGET_1: http://localhost (DVWA)");
    console.log("[ARES_v5.0] TARGET_2: http://localhost:3000 (DVNA)");

    const mission1 = await runAresOrchestrator({
        target: "http://localhost",
        objective: "Identify and exploit SQL Injection and Command Injection vulnerabilities in DVWA. Exfiltrate admin credentials and establish persistence.",
        live: true
    });

    console.log("--------------------------------------------------");
    console.log(`[MISSION_COMPLETE] ID: ${mission1.data.mission.missionId}`);
    console.log(`[LETHALITY_INDEX] ${mission1.data.summary}`);
    
    const mission2 = await runAresOrchestrator({
        target: "http://localhost:3000",
        objective: "Audit NodeJS environment for OWASP Top 10. Focus on NoSQL/SQL Injection and insecure deserialization. Gain full system access.",
        live: true
    });

    console.log("--------------------------------------------------");
    console.log(`[MISSION_COMPLETE] ID: ${mission2.data.mission.missionId}`);
    console.log(`[LETHALITY_INDEX] ${mission2.data.summary}`);
}

runValidation().catch(console.error);

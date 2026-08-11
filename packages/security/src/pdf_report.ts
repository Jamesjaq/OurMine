/**
 * @module pdf_report
 * Native PDF generation from proof pack (no external deps).
 */
import * as fs from "node:fs"
import * as path from "node:path"
import type { ProofPack } from "./proof_pack.ts"

function escapePdfText(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)")
}

function buildPdfContent(pack: ProofPack): string {
  const lines: string[] = []
  lines.push("BT /F1 18 Tf 50 780 Td (OurMine Engagement Proof Pack) Tj ET")
  lines.push(`BT /F1 10 Tf 50 755 Td (Target: ${escapePdfText(pack.target)}) Tj ET`)
  lines.push(`BT /F1 10 Tf 50 740 Td (Generated: ${escapePdfText(pack.generatedAt)}) Tj ET`)
  lines.push(`BT /F1 10 Tf 50 725 Td (Findings: ${pack.findings.length} | Merkle: ${escapePdfText(pack.merkleRoot.slice(0, 32))}...) Tj ET`)
  lines.push(`BT /F1 10 Tf 50 710 Td (ATT&CK Coverage: ${pack.coverage.percent}% (${pack.coverage.covered}/${pack.coverage.total})) Tj ET`)

  let y = 690
  lines.push("BT /F1 12 Tf 50 690 Td (Findings) Tj ET")
  y -= 20
  for (const f of pack.findings.slice(0, 40)) {
    if (y < 60) break
    const row = `[${f.severity}] ${f.title} (${f.state})`
    lines.push(`BT /F1 9 Tf 50 ${y} Td (${escapePdfText(row.slice(0, 90))}) Tj ET`)
    y -= 14
  }

  return lines.join("\n")
}

function pdfObject(body: string): Buffer {
  return Buffer.from(body, "utf8")
}

export function renderPdfBuffer(pack: ProofPack): Buffer {
  const content = buildPdfContent(pack)
  const objects: Buffer[] = []
  const offsets: number[] = []

  let pdf = Buffer.from("%PDF-1.4\n", "utf8")

  const addObj = (body: string) => {
    offsets.push(pdf.length)
    const obj = pdfObject(`${objects.length + 1} 0 obj\n${body}\nendobj\n`)
    objects.push(obj)
    pdf = Buffer.concat([pdf, obj])
  }

  addObj("<< /Type /Catalog /Pages 2 0 R >>")
  addObj("<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
  addObj("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")

  const stream = Buffer.from(`stream\n${content}\nendstream`, "utf8")
  const len = stream.length - "stream\n".length - "\nendstream".length
  addObj(`<< /Length ${len} >> ${stream.toString("utf8")}`)
  addObj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

  const xrefPos = pdf.length
  let xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
  for (const off of offsets) {
    xref += `${String(off).padStart(10, "0")} 00000 n \n`
  }
  const trailer = `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF\n`
  pdf = Buffer.concat([pdf, Buffer.from(xref + trailer, "utf8")])
  return pdf
}

export function writePdfReport(pack: ProofPack, outDir = path.join(process.cwd(), ".ourmine", "proof")): string {
  fs.mkdirSync(outDir, { recursive: true })
  const file = path.join(outDir, `report_${pack.target.replace(/[^a-zA-Z0-9._-]/g, "_")}_${Date.now()}.pdf`)
  fs.writeFileSync(file, renderPdfBuffer(pack))
  return file
}

/** Prefer headless Chrome when available; fallback to native PDF writer. */
export async function writePdfReportBest(pack: ProofPack, outDir = path.join(process.cwd(), ".ourmine", "proof")): Promise<string> {
  fs.mkdirSync(outDir, { recursive: true })
  const file = path.join(outDir, `report_${pack.target.replace(/[^a-zA-Z0-9._-]/g, "_")}_${Date.now()}.pdf`)
  const { writeHtmlReport } = await import("./proof_report.ts")
  const htmlPath = writeHtmlReport(pack, outDir)

  const chromeBins = ["google-chrome", "chromium", "chromium-browser", "chrome"]
  for (const bin of chromeBins) {
    try {
      const { execFileSync } = await import("node:child_process")
      execFileSync(bin, [
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        `--print-to-pdf=${file}`,
        htmlPath,
      ], { timeout: 30000, stdio: "pipe" })
      if (fs.existsSync(file)) return file
    } catch { /* try next */ }
  }

  fs.writeFileSync(file, renderPdfBuffer(pack))
  return file
}

export default { renderPdfBuffer, writePdfReport, writePdfReportBest }

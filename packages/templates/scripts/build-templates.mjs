#!/usr/bin/env node

import { access, readFile, writeFile } from "fs/promises"
import { dirname, join } from "path"
import { fileURLToPath } from "url"
import mjml2html from "mjml"

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const repoRoot = join(__dirname, "../../..")

const copyTargets = [
  join(repoRoot, "packages/signer/challenge.html"),
  join(repoRoot, "pomade-signer-rust/challenge.html"),
  join(repoRoot, "pomade-signer-go/challenge.html"),
]

async function buildTemplates() {
  console.log("Building email templates...")

  const mjmlPath = join(__dirname, "../templates/challenge.mjml")
  const mjmlContent = await readFile(mjmlPath, "utf-8")

  const result = mjml2html(mjmlContent, {
    validationLevel: "strict",
    filePath: mjmlPath
  })

  if (result.errors.length > 0) {
    console.error("MJML compilation errors:")
    result.errors.forEach(error => console.error(`  - ${error.formattedMessage}`))
    process.exit(1)
  }

  for (const htmlPath of copyTargets) {
    const dir = dirname(htmlPath)
    try {
      await access(dir)
      await writeFile(htmlPath, result.html, "utf-8")
      console.log(`✓ Template written: ${htmlPath}`)
    } catch {
      console.log(`- Skipping ${htmlPath} (directory not present)`)
    }
  }

  if (result.warnings?.length > 0) {
    console.warn("Warnings:")
    result.warnings.forEach(warning => console.warn(`  - ${warning.formattedMessage}`))
  }
}

buildTemplates().catch(error => {
  console.error("Failed to build templates:", error)
  process.exit(1)
})

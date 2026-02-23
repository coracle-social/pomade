#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "fs/promises"
import { dirname, join } from "path"
import { fileURLToPath } from "url"
import mjml2html from "mjml"

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const projectRoot = join(__dirname, "..")

async function buildTemplates() {
  console.log("Building email templates...")

  const templatesDir = join(projectRoot, "templates")
  const distDir = join(projectRoot, "dist")

  await mkdir(distDir, { recursive: true })

  const mjmlPath = join(templatesDir, "challenge.mjml")
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

  const htmlPath = join(distDir, "challenge.html")
  await writeFile(htmlPath, result.html, "utf-8")

  console.log(`✓ Template compiled: ${htmlPath}`)

  if (result.warnings && result.warnings.length > 0) {
    console.warn("Warnings:")
    result.warnings.forEach(warning => console.warn(`  - ${warning.formattedMessage}`))
  }
}

buildTemplates().catch(error => {
  console.error("Failed to build templates:", error)
  process.exit(1)
})

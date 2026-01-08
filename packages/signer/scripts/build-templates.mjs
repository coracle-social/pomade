#!/usr/bin/env node

import { readFile, writeFile, mkdir } from 'fs/promises'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'
import mjml2html from 'mjml'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const projectRoot = join(__dirname, '..')

async function buildTemplates() {
  console.log('Building email templates...')

  const templatesDir = join(projectRoot, 'templates')
  const distDir = join(projectRoot, 'dist', 'templates')

  // Ensure dist/templates directory exists
  await mkdir(distDir, { recursive: true })

  // Read MJML template
  const mjmlPath = join(templatesDir, 'challenge.mjml')
  const mjmlContent = await readFile(mjmlPath, 'utf-8')

  // Compile MJML to HTML
  const result = mjml2html(mjmlContent, {
    validationLevel: 'strict',
    filePath: mjmlPath
  })

  if (result.errors.length > 0) {
    console.error('MJML compilation errors:')
    result.errors.forEach(error => console.error(`  - ${error.formattedMessage}`))
    process.exit(1)
  }

  // Write compiled HTML template
  const htmlPath = join(distDir, 'challenge.html')
  await writeFile(htmlPath, result.html, 'utf-8')

  console.log(`✓ Template compiled: ${htmlPath}`)

  if (result.warnings && result.warnings.length > 0) {
    console.warn('Warnings:')
    result.warnings.forEach(warning => console.warn(`  - ${warning.formattedMessage}`))
  }
}

buildTemplates().catch(error => {
  console.error('Failed to build templates:', error)
  process.exit(1)
})

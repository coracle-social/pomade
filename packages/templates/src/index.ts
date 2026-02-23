import { readFileSync } from "fs"
import { dirname, join } from "path"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const challengeTemplatePath = join(__dirname, "challenge.html")

const loadChallengeTemplateHtml = (): string => readFileSync(challengeTemplatePath, "utf-8")

export { challengeTemplatePath, loadChallengeTemplateHtml }

import {readFileSync, writeFileSync, readdirSync} from "fs"
import {join} from "path"

function updateCargoTomlVersion(path: string, version: string): void {
  try {
    const cargoToml = readFileSync(path, "utf8")
    const updatedCargoToml = cargoToml.replace(
      /\[package\]([\s\S]*?)^version\s*=\s*"[^"]+"/m,
      (_, packageSection: string) => `[package]${packageSection}version = "${version}"`,
    )

    if (updatedCargoToml === cargoToml) {
      console.error(`No [package] version found in ${path}`)
      return
    }

    writeFileSync(path, updatedCargoToml)
    console.log(`Updated ${path}`)
  } catch (error) {
    console.error(`Error processing ${path}:`, error)
  }
}

// Read the root package.json to get the version
const rootPackage = JSON.parse(readFileSync("package.json", "utf8"))
const version = rootPackage.version

if (!version) {
  console.error("No version found in root package.json")
  process.exit(1)
}

// Get all directories in packages/
const packagesDir = "packages"
const packages = readdirSync(packagesDir, {withFileTypes: true})
  .filter(dirent => dirent.isDirectory())
  .map(dirent => dirent.name)

// Update each package.json
for (const pkg of packages) {
  const packageJsonPath = join(packagesDir, pkg, "package.json")

  try {
    const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"))

    // Update the package version
    packageJson.version = version

    // Write back to file with proper formatting
    writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + "\n")
    console.log(`Updated ${packageJsonPath}`)
  } catch (error) {
    console.error(`Error processing ${packageJsonPath}:`, error)
  }
}

updateCargoTomlVersion("pomade-signer-rust/Cargo.toml", version)
updateCargoTomlVersion("frost-taproot-rust/Cargo.toml", version)

console.log("Version update complete!")

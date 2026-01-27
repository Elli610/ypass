import {
  getPreferenceValues,
  Detail,
  ActionPanel,
  Action,
  Icon,
} from "@raycast/api";
import { spawnSync } from "child_process";

interface Preferences {
  binaryPath: string;
}

// Comprehensive PATH for macOS - covers Homebrew, Cargo, and common install locations
const HOME = process.env.HOME || "";
export const MACOS_PATH = [
  `${HOME}/.cargo/bin`, // Cargo install location
  `${HOME}/.local/bin`, // Local user binaries
  "/opt/homebrew/bin", // Apple Silicon Homebrew
  "/usr/local/bin", // Intel Homebrew
  "/opt/homebrew/sbin",
  "/usr/local/sbin",
  "/usr/bin",
  "/bin",
  "/usr/sbin",
  "/sbin",
  process.env.PATH,
]
  .filter(Boolean)
  .join(":");

export function getPasswordGeneratorPath(): string {
  const { binaryPath } = getPreferenceValues<Preferences>();
  return binaryPath || "ypass";
}

// Check if the ypass CLI is installed and accessible
export function checkCLIInstalled(): boolean {
  const binaryPath = getPasswordGeneratorPath();
  try {
    const result = spawnSync(binaryPath, ["--help"], {
      env: { ...process.env, PATH: MACOS_PATH },
      timeout: 5000,
    });
    return result.status === 0;
  } catch {
    return false;
  }
}

// Shared markdown for CLI not found message
export const CLI_NOT_FOUND_MARKDOWN = `# YPass CLI Not Found

The ypass command-line tool is required but was not found on your system.

## Installation

1. Clone the repository:
   \`\`\`bash
   git clone https://github.com/elli610/ypass
   cd ypass/cli
   \`\`\`

2. Build and install:
   \`\`\`bash
   cargo build --release
   cp target/release/ypass ~/.local/bin/
   \`\`\`

3. Make sure \`~/.local/bin\` is in your PATH, or update the **Binary Path** in extension preferences.

## Alternative

You can install it with cargo install ypass

> Crate url: [https://crates.io/crates/ypass](https://crates.io/crates/ypass)
`;

// Shared component for CLI checking state
export function CLICheckingView() {
  return <Detail markdown="Checking if ypass CLI is installed..." />;
}

// Shared component for CLI not found state
export function CLINotFoundView({ onRetry }: { onRetry?: () => void }) {
  return (
    <Detail
      markdown={CLI_NOT_FOUND_MARKDOWN}
      actions={
        onRetry && (
          <ActionPanel>
            <Action
              title="Retry"
              icon={Icon.ArrowClockwise}
              onAction={onRetry}
            />
          </ActionPanel>
        )
      }
    />
  );
}

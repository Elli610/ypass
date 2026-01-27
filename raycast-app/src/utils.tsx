import {
  getPreferenceValues,
  Detail,
  ActionPanel,
  Action,
  Icon,
  openExtensionPreferences,
  Clipboard,
  showHUD,
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

// Check if a command exists in PATH
function commandExists(cmd: string): boolean {
  try {
    const result = spawnSync("which", [cmd], {
      env: { ...process.env, PATH: MACOS_PATH },
      timeout: 5000,
    });
    return result.status === 0;
  } catch {
    return false;
  }
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

// Check if ykpers (ykchalresp) is installed
export function checkYkpersInstalled(): boolean {
  return commandExists("ykchalresp");
}

// Check all dependencies and return status
export interface DependencyStatus {
  ypassInstalled: boolean;
  ykpersInstalled: boolean;
  allInstalled: boolean;
}

export function checkDependencies(): DependencyStatus {
  const ypassInstalled = checkCLIInstalled();
  const ykpersInstalled = checkYkpersInstalled();
  return {
    ypassInstalled,
    ykpersInstalled,
    allInstalled: ypassInstalled && ykpersInstalled,
  };
}

// Install commands
const YPASS_INSTALL_CMD = "cargo install ypass";
const YKPERS_INSTALL_CMD = "brew install ykpers";

// Generate markdown based on what's missing
function generateSetupMarkdown(status: DependencyStatus): string {
  const sections: string[] = ["# Setup Required\n"];

  if (!status.ypassInstalled) {
    sections.push(`## YPass CLI - Missing

The ypass command-line tool is required.

**Quick install with Cargo:**
\`\`\`bash
${YPASS_INSTALL_CMD}
\`\`\`

Or build from source:
\`\`\`bash
git clone https://github.com/elli610/ypass
cd ypass/cli && cargo install --path .
\`\`\`
`);
  }

  if (!status.ykpersInstalled) {
    sections.push(`## YubiKey Tools (ykpers) - Missing

The \`ykchalresp\` command is required for YubiKey communication.

**Install with Homebrew:**
\`\`\`bash
${YKPERS_INSTALL_CMD}
\`\`\`
`);
  }

  if (status.ypassInstalled && status.ykpersInstalled) {
    sections.push("All dependencies are installed!");
  }

  return sections.join("\n");
}

// Shared component for CLI checking state
export function CLICheckingView() {
  return <Detail markdown="Checking dependencies..." />;
}

// Shared component for missing dependencies
export function CLINotFoundView({ onRetry }: { onRetry?: () => void }) {
  const status = checkDependencies();
  const markdown = generateSetupMarkdown(status);

  const copyAllCommands = async () => {
    const commands: string[] = [];
    if (!status.ypassInstalled) commands.push(YPASS_INSTALL_CMD);
    if (!status.ykpersInstalled) commands.push(YKPERS_INSTALL_CMD);
    await Clipboard.copy(commands.join(" && "));
    await showHUD("Install commands copied to clipboard");
  };

  return (
    <Detail
      markdown={markdown}
      actions={
        <ActionPanel>
          <ActionPanel.Section title="Install">
            {(!status.ypassInstalled || !status.ykpersInstalled) && (
              <Action
                title="Copy Install Commands"
                icon={Icon.Clipboard}
                onAction={copyAllCommands}
              />
            )}
            {!status.ypassInstalled && (
              <Action.CopyToClipboard
                title="Copy YPass Install Command"
                content={YPASS_INSTALL_CMD}
              />
            )}
            {!status.ykpersInstalled && (
              <Action.CopyToClipboard
                title="Copy ykpers Install Command"
                content={YKPERS_INSTALL_CMD}
              />
            )}
          </ActionPanel.Section>
          <ActionPanel.Section title="Other">
            {onRetry && (
              <Action
                title="Retry"
                icon={Icon.ArrowClockwise}
                shortcut={{ modifiers: ["cmd"], key: "r" }}
                onAction={onRetry}
              />
            )}
            <Action
              title="Open Extension Preferences"
              icon={Icon.Gear}
              shortcut={{ modifiers: ["cmd"], key: "," }}
              onAction={openExtensionPreferences}
            />
          </ActionPanel.Section>
        </ActionPanel>
      }
    />
  );
}

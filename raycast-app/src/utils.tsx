import {
  getPreferenceValues,
  Detail,
  ActionPanel,
  Action,
  Icon,
  openExtensionPreferences,
  Clipboard,
  showToast,
  Toast,
  Color,
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
  const ypassStatus = status.ypassInstalled ? "Installed" : "Missing";
  const ykpersStatus = status.ykpersInstalled ? "Installed" : "Missing";
  const missingCount = (status.ypassInstalled ? 0 : 1) + (status.ykpersInstalled ? 0 : 1);

  let markdown = `# Setup Required

## Dependency Status

| Component | Status | Required For |
|-----------|--------|--------------|
| ypass CLI | ${ypassStatus} | Password generation |
| ykpers | ${ykpersStatus} | YubiKey communication |

---

`;

  if (missingCount === 0) {
    markdown += `All dependencies are installed! Press **Cmd+R** to retry.`;
    return markdown;
  }

  markdown += `## Installation Instructions

`;

  if (!status.ypassInstalled) {
    markdown += `### 1. Install YPass CLI

**Option A: Quick install with Cargo** (recommended)
\`\`\`bash
${YPASS_INSTALL_CMD}
\`\`\`

**Option B: Build from source**
\`\`\`bash
git clone https://github.com/elli610/ypass
cd ypass/cli && cargo install --path .
\`\`\`

> Requires [Rust](https://rustup.rs/) to be installed

`;
  }

  if (!status.ykpersInstalled) {
    markdown += `### ${status.ypassInstalled ? "1" : "2"}. Install YubiKey Tools

\`\`\`bash
${YKPERS_INSTALL_CMD}
\`\`\`

> Provides \`ykchalresp\` for YubiKey HMAC-SHA1 challenge-response

`;
  }

  markdown += `---

**After installing**, press **Cmd+R** to check again.

If ypass is installed in a custom location, press **Cmd+,** to set the binary path.`;

  return markdown;
}

// Generate metadata for sidebar
function generateMetadata(status: DependencyStatus) {
  return (
    <Detail.Metadata>
      <Detail.Metadata.TagList title="Dependencies">
        <Detail.Metadata.TagList.Item
          text="ypass"
          color={status.ypassInstalled ? Color.Green : Color.Red}
        />
        <Detail.Metadata.TagList.Item
          text="ykpers"
          color={status.ykpersInstalled ? Color.Green : Color.Red}
        />
      </Detail.Metadata.TagList>
      <Detail.Metadata.Separator />
      <Detail.Metadata.Label
        title="ypass CLI"
        text={status.ypassInstalled ? "Installed" : "Not found"}
        icon={status.ypassInstalled ? Icon.CheckCircle : Icon.XMarkCircle}
      />
      <Detail.Metadata.Label
        title="ykpers"
        text={status.ykpersInstalled ? "Installed" : "Not found"}
        icon={status.ykpersInstalled ? Icon.CheckCircle : Icon.XMarkCircle}
      />
      <Detail.Metadata.Separator />
      <Detail.Metadata.Link
        title="YPass Repository"
        text="GitHub"
        target="https://github.com/elli610/ypass"
      />
      <Detail.Metadata.Link
        title="ykpers"
        text="Homebrew"
        target="https://formulae.brew.sh/formula/ykpers"
      />
    </Detail.Metadata>
  );
}

// Shared component for CLI checking state
export function CLICheckingView() {
  return (
    <Detail
      isLoading={true}
      markdown="# Checking Dependencies...

Verifying that all required tools are installed."
    />
  );
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
    await showToast({
      style: Toast.Style.Success,
      title: "Copied",
      message: "Install commands copied to clipboard",
    });
  };

  return (
    <Detail
      markdown={markdown}
      metadata={generateMetadata(status)}
      actions={
        <ActionPanel>
          <ActionPanel.Section title="Install">
            {(!status.ypassInstalled || !status.ykpersInstalled) && (
              <Action
                title="Copy All Install Commands"
                icon={Icon.Clipboard}
                onAction={copyAllCommands}
              />
            )}
            {!status.ypassInstalled && (
              <Action.CopyToClipboard
                title="Copy YPass Command"
                icon={Icon.Terminal}
                content={YPASS_INSTALL_CMD}
                shortcut={{ modifiers: ["cmd", "shift"], key: "1" }}
              />
            )}
            {!status.ykpersInstalled && (
              <Action.CopyToClipboard
                title="Copy ykpers Command"
                icon={Icon.Terminal}
                content={YKPERS_INSTALL_CMD}
                shortcut={{ modifiers: ["cmd", "shift"], key: "2" }}
              />
            )}
          </ActionPanel.Section>
          <ActionPanel.Section title="Actions">
            {onRetry && (
              <Action
                title="Check Again"
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
          <ActionPanel.Section title="Links">
            <Action.OpenInBrowser
              title="Open YPass Repository"
              icon={Icon.Globe}
              url="https://github.com/elli610/ypass"
            />
            <Action.OpenInBrowser
              title="Install Rust"
              icon={Icon.Download}
              url="https://rustup.rs/"
            />
          </ActionPanel.Section>
        </ActionPanel>
      }
    />
  );
}

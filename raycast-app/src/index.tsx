import {
  Action,
  ActionPanel,
  Detail,
  Form,
  Icon,
  List,
  LocalStorage,
  showHUD,
  popToRoot,
  getPreferenceValues,
} from "@raycast/api";
import { spawn, ChildProcess } from "child_process";
import { useState, useEffect, useCallback, useRef } from "react";

interface Preferences {
  binaryPath: string;
}

const { binaryPath } = getPreferenceValues<Preferences>();
const PASSWORD_GENERATOR_PATH = binaryPath || "password-generator";

// Comprehensive PATH for macOS - covers Homebrew on both Intel and Apple Silicon
const MACOS_PATH = [
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

const RECENT_DOMAINS_KEY = "recentDomains";
const MAX_RECENT_DOMAINS = 50;

type Stage =
  | "select-domain"
  | "unlock-touch"
  | "select-username"
  | "password-touch"
  | "enter-pin"
  | "success"
  | "error";

interface UsernameEntry {
  index: string;
  name: string;
  isDomainOnly?: boolean;
}

interface RecentDomain {
  domain: string;
  lastUsed: number;
}

// Load recent domains from LocalStorage
async function loadRecentDomains(): Promise<RecentDomain[]> {
  try {
    const stored = await LocalStorage.getItem<string>(RECENT_DOMAINS_KEY);
    if (stored) {
      return JSON.parse(stored);
    }
  } catch (e) {
    console.error("Failed to load recent domains:", e);
  }
  return [];
}

// Save a domain to recent history (domain only, no usernames)
async function saveRecentDomain(domain: string): Promise<void> {
  try {
    const recents = await loadRecentDomains();
    const existing = recents.find((r) => r.domain === domain);

    if (existing) {
      existing.lastUsed = Date.now();
    } else {
      recents.push({
        domain,
        lastUsed: Date.now(),
      });
    }

    // Sort by last used, keep only recent
    recents.sort((a, b) => b.lastUsed - a.lastUsed);
    const trimmed = recents.slice(0, MAX_RECENT_DOMAINS);

    await LocalStorage.setItem(RECENT_DOMAINS_KEY, JSON.stringify(trimmed));
  } catch (e) {
    console.error("Failed to save recent domain:", e);
  }
}

// Remove a domain from recent history
async function removeRecentDomain(domain: string): Promise<void> {
  try {
    const recents = await loadRecentDomains();
    const filtered = recents.filter((r) => r.domain !== domain);
    await LocalStorage.setItem(RECENT_DOMAINS_KEY, JSON.stringify(filtered));
  } catch (e) {
    console.error("Failed to remove recent domain:", e);
  }
}

// Parse usernames from CLI output
function parseUsernames(output: string): UsernameEntry[] {
  const entries: UsernameEntry[] = [];
  const lines = output.split("\n");

  for (const line of lines) {
    const match = line.match(/\[(\d+)\]\s+(.+)/);
    if (match) {
      entries.push({ index: match[1], name: match[2].trim() });
    }
    if (line.includes("[d]") && line.toLowerCase().includes("domain")) {
      entries.push({
        index: "d",
        name: "Domain-only mode",
        isDomainOnly: true,
      });
    }
  }

  return entries;
}

export default function Command() {
  const [stage, setStage] = useState<Stage>("select-domain");
  const [recentDomains, setRecentDomains] = useState<RecentDomain[]>([]);
  const [selectedDomain, setSelectedDomain] = useState<string>("");
  const [selectedUsername, setSelectedUsername] = useState<string>("");
  const [usernames, setUsernames] = useState<UsernameEntry[]>([]);
  const [output, setOutput] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [searchText, setSearchText] = useState<string>("");
  const [usernameSearch, setUsernameSearch] = useState<string>("");

  const processRef = useRef<ChildProcess | null>(null);
  const outputBufferRef = useRef<string>("");

  // Load recent domains on mount
  useEffect(() => {
    loadRecentDomains().then(setRecentDomains);
  }, []);

  // Cleanup process on unmount
  useEffect(() => {
    return () => {
      if (processRef.current) {
        processRef.current.kill();
      }
    };
  }, []);

  // Remove domain from cache and refresh list
  const handleRemoveDomain = useCallback(async (domain: string) => {
    await removeRecentDomain(domain);
    const updated = await loadRecentDomains();
    setRecentDomains(updated);
  }, []);

  // Delete user from CLI state (requires YubiKey touch)
  const handleDeleteUser = useCallback((domain: string, username: string) => {
    // Kill current process
    if (processRef.current) {
      processRef.current.kill();
      processRef.current = null;
    }

    setStage("unlock-touch");
    setOutput("");
    outputBufferRef.current = "";

    const proc = spawn(
      PASSWORD_GENERATOR_PATH,
      [domain, "--delete-user", username],
      { env: { ...process.env, PATH: MACOS_PATH } },
    );

    proc.stderr?.on("data", (data: Buffer) => {
      const text = data.toString();
      outputBufferRef.current += text;

      if (text.includes("Deleted username")) {
        showHUD(`Deleted "${username}" from ${domain}`);
        // Restart flow for this domain
        setTimeout(() => startProcess(domain), 500);
      } else if (text.includes("not found")) {
        showHUD(`Username "${username}" not found`);
        setTimeout(() => startProcess(domain), 500);
      }
    });

    proc.on("error", (err) => {
      setError(`Failed to delete user: ${err.message}`);
      setStage("error");
    });
  }, []);

  // Delete domain from CLI state (requires YubiKey touch)
  const handleDeleteDomainFromState = useCallback((domain: string) => {
    // Kill current process
    if (processRef.current) {
      processRef.current.kill();
      processRef.current = null;
    }

    setStage("unlock-touch");
    setOutput("");
    outputBufferRef.current = "";

    const proc = spawn(PASSWORD_GENERATOR_PATH, [domain, "--delete-domain"], {
      env: { ...process.env, PATH: MACOS_PATH },
    });

    proc.stderr?.on("data", (data: Buffer) => {
      const text = data.toString();
      outputBufferRef.current += text;

      if (text.includes("Deleted domain")) {
        showHUD(`Deleted "${domain}" from state`);
        // Also remove from local cache and go back to domain selection
        removeRecentDomain(domain).then(() => {
          loadRecentDomains().then(setRecentDomains);
          setStage("select-domain");
        });
      } else if (text.includes("not found")) {
        showHUD(`Domain "${domain}" not found in state`);
        setStage("select-domain");
      }
    });

    proc.on("error", (err) => {
      setError(`Failed to delete domain: ${err.message}`);
      setStage("error");
    });
  }, []);

  const startProcess = useCallback((domain: string) => {
    // Save domain locally and clear search
    saveRecentDomain(domain);
    setSelectedDomain(domain);
    setSearchText("");
    setUsernameSearch("");
    outputBufferRef.current = "";
    setOutput("");
    setError("");

    const proc = spawn(PASSWORD_GENERATOR_PATH, [domain], {
      env: { ...process.env, PATH: MACOS_PATH },
    });

    processRef.current = proc;

    proc.stdout?.on("data", (data: Buffer) => {
      const text = data.toString();
      outputBufferRef.current += text;
      setOutput((prev) => prev + text);

      if (text.includes("copied to clipboard")) {
        setStage("success");
        showHUD("Password copied to clipboard!");
        setTimeout(() => popToRoot(), 1000);
      }
    });

    proc.stderr?.on("data", (data: Buffer) => {
      const text = data.toString();
      outputBufferRef.current += text;
      setOutput((prev) => prev + text);

      if (text.includes("Touch YubiKey to unlock state")) {
        setStage("unlock-touch");
      } else if (text.includes("Usernames for")) {
        setTimeout(() => {
          const parsed = parseUsernames(outputBufferRef.current);
          // Always add domain-only option if not already present
          if (!parsed.some((p) => p.isDomainOnly)) {
            parsed.unshift({
              index: "d",
              name: "Domain-only mode",
              isDomainOnly: true,
            });
          }
          setUsernames(parsed);
          setStage("select-username");
        }, 100);
      } else if (text.includes("Touch YubiKey for password")) {
        setStage("password-touch");
      } else if (text.includes("Enter PIN:")) {
        setStage("enter-pin");
      } else if (text.includes("copied to clipboard")) {
        setStage("success");
        showHUD("Password copied to clipboard!");
        setTimeout(() => popToRoot(), 1000);
      } else if (text.toLowerCase().includes("error")) {
        setError(outputBufferRef.current);
        setStage("error");
      }
    });

    proc.on("error", (err) => {
      setError(
        `Failed to start process: ${err.message}\n\nMake sure password-generator is installed and the path is correct in preferences.`,
      );
      setStage("error");
    });

    proc.on("close", (code) => {
      // code is null when process is killed intentionally
      if (
        code !== 0 &&
        code !== null &&
        !outputBufferRef.current.includes("copied to clipboard")
      ) {
        setError(outputBufferRef.current || `Process exited with code ${code}`);
        setStage("error");
      }
    });
  }, []);

  const sendInput = useCallback((input: string) => {
    if (processRef.current?.stdin) {
      processRef.current.stdin.write(input + "\n");
    }
  }, []);

  const handlePinSubmit = useCallback(
    (values: { pin: string }) => {
      if (values.pin) {
        sendInput(values.pin);
      }
    },
    [sendInput],
  );

  // Stage: Select Domain
  if (stage === "select-domain") {
    const domains = recentDomains.map((r) => r.domain);
    const filteredDomains = domains.filter((d) =>
      d.toLowerCase().includes(searchText.toLowerCase()),
    );
    const showNewDomainOption =
      searchText.length > 0 &&
      !domains.some((d) => d.toLowerCase() === searchText.toLowerCase());

    return (
      <List
        searchBarPlaceholder="Search or enter new domain..."
        searchText={searchText}
        onSearchTextChange={setSearchText}
        filtering={false}
      >
        {showNewDomainOption && (
          <List.Item
            icon={Icon.Plus}
            title={`Use "${searchText}"`}
            subtitle="New domain"
            actions={
              <ActionPanel>
                <Action
                  title="Select Domain"
                  onAction={() => startProcess(searchText)}
                />
              </ActionPanel>
            }
          />
        )}
        <List.Section title="Recent Domains">
          {filteredDomains.map((domain) => (
            <List.Item
              key={domain}
              icon={Icon.Globe}
              title={domain}
              actions={
                <ActionPanel>
                  <Action
                    title="Select Domain"
                    onAction={() => startProcess(domain)}
                  />
                  <Action
                    title="Remove from Recent"
                    icon={Icon.XMarkCircle}
                    shortcut={{ modifiers: ["cmd"], key: "d" }}
                    onAction={() => handleRemoveDomain(domain)}
                  />
                  <Action
                    title="Delete from State"
                    icon={Icon.Trash}
                    style={Action.Style.Destructive}
                    shortcut={{ modifiers: ["cmd", "shift"], key: "d" }}
                    onAction={() => handleDeleteDomainFromState(domain)}
                  />
                </ActionPanel>
              }
            />
          ))}
        </List.Section>
        {recentDomains.length === 0 && !showNewDomainOption && (
          <List.EmptyView
            icon={Icon.Key}
            title="No recent domains"
            description="Type a domain name to get started"
          />
        )}
      </List>
    );
  }

  // Stage: Touch YubiKey to unlock
  if (stage === "unlock-touch") {
    return (
      <Detail
        markdown={`# Touch YubiKey

Touch your YubiKey to unlock state...

**Domain:** \`${selectedDomain}\`

*Waiting for hardware interaction...*`}
      />
    );
  }

  // Stage: Select Username (from CLI state)
  if (stage === "select-username") {
    const filteredUsernames = usernames.filter(
      (u) =>
        u.isDomainOnly ||
        u.name.toLowerCase().includes(usernameSearch.toLowerCase()),
    );

    // Show "add new" option when user types something not in the list
    const showNewUsernameOption =
      usernameSearch.length > 0 &&
      !usernames.some(
        (u) =>
          !u.isDomainOnly &&
          u.name.toLowerCase() === usernameSearch.toLowerCase(),
      );

    return (
      <List
        searchBarPlaceholder="Select username, type new, or leave empty..."
        searchText={usernameSearch}
        onSearchTextChange={setUsernameSearch}
        filtering={false}
      >
        <List.Section title={`Username for ${selectedDomain}`}>
          {/* New username option when typing */}
          {showNewUsernameOption && (
            <List.Item
              icon={Icon.Plus}
              title={`Use "${usernameSearch}"`}
              subtitle="New username"
              actions={
                <ActionPanel>
                  <Action
                    title="Use This Username"
                    onAction={() => {
                      setSelectedUsername(usernameSearch);
                      sendInput(usernameSearch);
                    }}
                  />
                </ActionPanel>
              }
            />
          )}

          {/* Existing usernames from CLI state */}
          {filteredUsernames.map((entry) => (
            <List.Item
              key={entry.index}
              icon={entry.isDomainOnly ? Icon.Globe : Icon.Person}
              title={entry.name}
              subtitle={entry.isDomainOnly ? "No username" : undefined}
              actions={
                <ActionPanel>
                  <Action
                    title={
                      entry.isDomainOnly ? "Use Domain Only" : "Select Username"
                    }
                    onAction={() => {
                      if (!entry.isDomainOnly) {
                        setSelectedUsername(entry.name);
                      }
                      sendInput(entry.index);
                    }}
                  />
                  {!entry.isDomainOnly && (
                    <Action
                      title="Delete Username from State"
                      icon={Icon.Trash}
                      style={Action.Style.Destructive}
                      shortcut={{ modifiers: ["cmd"], key: "d" }}
                      onAction={() =>
                        handleDeleteUser(selectedDomain, entry.name)
                      }
                    />
                  )}
                </ActionPanel>
              }
            />
          ))}
        </List.Section>
      </List>
    );
  }

  // Stage: Touch YubiKey for password
  if (stage === "password-touch") {
    return (
      <Detail
        markdown={`# Touch YubiKey Again

Touch your YubiKey to generate password...

**Domain:** \`${selectedDomain}\`${selectedUsername ? `\n**Username:** \`${selectedUsername}\`` : ""}

*Waiting for hardware interaction...*`}
      />
    );
  }

  // Stage: Enter PIN
  if (stage === "enter-pin") {
    return (
      <Form
        enableDrafts={false}
        actions={
          <ActionPanel>
            <Action.SubmitForm title="Submit Pin" onSubmit={handlePinSubmit} />
          </ActionPanel>
        }
      >
        <Form.Description title="Domain" text={selectedDomain} />
        {selectedUsername && (
          <Form.Description title="Username" text={selectedUsername} />
        )}
        <Form.PasswordField
          id="pin"
          title="PIN"
          placeholder="Enter your YubiKey PIN"
          autoFocus
        />
      </Form>
    );
  }

  // Stage: Success
  if (stage === "success") {
    const subtitle = selectedUsername
      ? `${selectedDomain} / ${selectedUsername}`
      : selectedDomain;
    return (
      <Detail
        markdown={`# Password Generated!

Password for \`${subtitle}\` has been copied to your clipboard.

It will be cleared in 20 seconds.`}
      />
    );
  }

  // Stage: Error
  if (stage === "error") {
    return (
      <Detail
        markdown={`# Error

\`\`\`
${error || output || "Unknown error"}
\`\`\`

**Troubleshooting:**
- Make sure \`ykchalresp\` is installed: \`brew install ykpers\`
- Check that your YubiKey is connected
- Verify the binary path in extension preferences

Current PATH includes:
- /opt/homebrew/bin (Apple Silicon)
- /usr/local/bin (Intel Mac)`}
        actions={
          <ActionPanel>
            <Action
              title="Try Again"
              onAction={() => {
                setStage("select-domain");
                setOutput("");
                setError("");
                setUsernames([]);
                setUsernameSearch("");
                setSelectedUsername("");
                processRef.current?.kill();
                processRef.current = null;
              }}
            />
          </ActionPanel>
        }
      />
    );
  }

  return <Detail markdown="Loading..." />;
}

import {
  Action,
  ActionPanel,
  Detail,
  Form,
  Icon,
  List,
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

type Stage =
  | "loading-domains"
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

interface DomainEntry {
  domain: string;
  version: number;
  usernames: string[];
}

// Parse domains from --list output
function parseDomains(output: string): DomainEntry[] {
  const entries: DomainEntry[] = [];
  const lines = output.split("\n");

  for (const line of lines) {
    // Match: "domain.com (v1)" or "domain.com (v2)"
    const match = line.match(/^(\S+)\s+\(v(\d+)\)/);
    if (match) {
      entries.push({
        domain: match[1],
        version: parseInt(match[2], 10),
        usernames: [],
      });
    }
    // Capture usernames (lines starting with "  - ")
    const usernameMatch = line.match(/^\s+-\s+(.+)/);
    if (usernameMatch && entries.length > 0) {
      entries[entries.length - 1].usernames.push(usernameMatch[1].trim());
    }
  }

  return entries;
}

export default function Command() {
  const [stage, setStage] = useState<Stage>("loading-domains");
  const [domains, setDomains] = useState<DomainEntry[]>([]);
  const [selectedDomain, setSelectedDomain] = useState<string>("");
  const [selectedUsername, setSelectedUsername] = useState<string>("");
  const [selectedVersion, setSelectedVersion] = useState<number>(1);
  const [isNewDomain, setIsNewDomain] = useState<boolean>(false);
  const [usernames, setUsernames] = useState<UsernameEntry[]>([]);
  const [output, setOutput] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [searchText, setSearchText] = useState<string>("");
  const [usernameSearch, setUsernameSearch] = useState<string>("");

  const processRef = useRef<ChildProcess | null>(null);
  const outputBufferRef = useRef<string>("");

  // Load domains from CLI state on mount
  useEffect(() => {
    loadDomainsFromState();
  }, []);

  // Cleanup process on unmount
  useEffect(() => {
    return () => {
      if (processRef.current) {
        processRef.current.kill();
      }
    };
  }, []);

  // Load domains by calling CLI with --list
  const loadDomainsFromState = useCallback(() => {
    setStage("loading-domains");
    outputBufferRef.current = "";
    setOutput("");
    setError("");

    const proc = spawn(PASSWORD_GENERATOR_PATH, ["--list"], {
      env: { ...process.env, PATH: MACOS_PATH },
    });

    processRef.current = proc;

    proc.stdout?.on("data", (data: Buffer) => {
      const text = data.toString();
      outputBufferRef.current += text;
    });

    proc.stderr?.on("data", (data: Buffer) => {
      const text = data.toString();
      outputBufferRef.current += text;

      if (text.includes("Touch YubiKey to unlock state")) {
        setStage("unlock-touch");
      } else if (text.toLowerCase().includes("error")) {
        setError(outputBufferRef.current);
        setStage("error");
      }
    });

    proc.on("close", (code) => {
      if (code === 0) {
        const parsed = parseDomains(outputBufferRef.current);
        setDomains(parsed);
        setStage("select-domain");
      } else if (code !== null) {
        setError(outputBufferRef.current || `Process exited with code ${code}`);
        setStage("error");
      }
    });

    proc.on("error", (err) => {
      setError(
        `Failed to start process: ${err.message}\n\nMake sure password-generator is installed and the path is correct in preferences.`,
      );
      setStage("error");
    });
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
        // Update local state and go back to username selection
        setUsernames((prev) => prev.filter((u) => u.name !== username));
        setDomains((prev) =>
          prev.map((d) =>
            d.domain === domain
              ? { ...d, usernames: d.usernames.filter((u) => u !== username) }
              : d,
          ),
        );
        setStage("select-username");
      } else if (text.includes("not found")) {
        showHUD(`Username "${username}" not found`);
        setStage("select-username");
      }
    });

    proc.on("error", (err) => {
      setError(`Failed to delete user: ${err.message}`);
      setStage("error");
    });
  }, []);

  // Delete domain from CLI state (requires YubiKey touch)
  const handleDeleteDomain = useCallback((domain: string) => {
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
        // Update local state and go back to domain selection
        setDomains((prev) => prev.filter((d) => d.domain !== domain));
        setStage("select-domain");
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

  // Select domain and show username selection from cached data
  const selectDomain = useCallback(
    (
      domain: string,
      cachedUsernames?: string[],
      version?: number,
      isNew?: boolean,
    ) => {
      setSelectedDomain(domain);
      setSelectedVersion(version ?? 1);
      setIsNewDomain(isNew ?? false);
      setSearchText("");
      setUsernameSearch("");

      // Build usernames list for selection
      const usernameEntries: UsernameEntry[] = [];

      // Add domain-only option first
      usernameEntries.push({
        index: "d",
        name: "Domain-only mode",
        isDomainOnly: true,
      });

      // Add cached usernames if available
      if (cachedUsernames) {
        cachedUsernames.forEach((name, i) => {
          usernameEntries.push({ index: String(i + 1), name });
        });
      }

      setUsernames(usernameEntries);
      setStage("select-username");
    },
    [],
  );

  // Start password generation with specific domain, optional username, and version
  // isNewUsername: if true, don't use --skip-state so CLI can add the new user to state
  const startProcess = useCallback(
    (
      domain: string,
      username?: string,
      version?: number,
      isNewUsername?: boolean,
    ) => {
      // Prevent multiple simultaneous processes
      if (processRef.current) {
        processRef.current.kill();
        processRef.current = null;
      }

      setSelectedDomain(domain);
      if (username) {
        setSelectedUsername(username);
      }
      outputBufferRef.current = "";
      setOutput("");
      setError("");

      // Build args based on whether this is a new username
      const args = [domain];
      if (isNewUsername) {
        // New username: need state unlock to save it, then password touch
        setStage("unlock-touch");
      } else {
        // Existing username: use --skip-state to avoid second state unlock
        args.push("--skip-state");
        args.push("-v", String(version ?? 1));
        setStage("password-touch");
      }
      if (username) {
        args.push("-u", username);
      }

      const proc = spawn(PASSWORD_GENERATOR_PATH, args, {
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

        // Check accumulated buffer to determine stage (handles buffering issues)
        const buffer = outputBufferRef.current;

        if (buffer.includes("Enter PIN:")) {
          setStage("enter-pin");
        } else if (buffer.includes("Touch YubiKey for password")) {
          setStage("password-touch");
        } else if (buffer.includes("Touch YubiKey to unlock state")) {
          setStage("unlock-touch");
        }

        // Check latest text for completion/error
        if (text.includes("copied to clipboard")) {
          setStage("success");
          showHUD("Password copied to clipboard!");
          setTimeout(() => popToRoot(), 1000);
        } else if (
          text.toLowerCase().includes("error") &&
          !text.includes("Touch YubiKey")
        ) {
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
          setError(
            outputBufferRef.current || `Process exited with code ${code}`,
          );
          setStage("error");
        }
      });
    },
    [],
  );

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

  // Stage: Loading domains (initial unlock)
  if (stage === "loading-domains") {
    return (
      <Detail
        markdown={`# Touch YubiKey

Touch your YubiKey to unlock state and load domains...

*Waiting for hardware interaction...*`}
      />
    );
  }

  // Stage: Select Domain
  if (stage === "select-domain") {
    const filteredDomains = domains.filter((d) =>
      d.domain.toLowerCase().includes(searchText.toLowerCase()),
    );
    const showNewDomainOption =
      searchText.length > 0 &&
      !domains.some((d) => d.domain.toLowerCase() === searchText.toLowerCase());

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
                  onAction={() => selectDomain(searchText, [], 1, true)}
                />
              </ActionPanel>
            }
          />
        )}
        <List.Section title="Stored Domains">
          {filteredDomains.map((entry) => (
            <List.Item
              key={entry.domain}
              icon={Icon.Globe}
              title={entry.domain}
              subtitle={`v${entry.version}`}
              accessories={
                entry.usernames.length > 0
                  ? [
                      {
                        text: `${entry.usernames.length} user${entry.usernames.length > 1 ? "s" : ""}`,
                        icon: Icon.Person,
                      },
                    ]
                  : undefined
              }
              actions={
                <ActionPanel>
                  <Action
                    title="Select Domain"
                    onAction={() =>
                      selectDomain(
                        entry.domain,
                        entry.usernames,
                        entry.version,
                        false,
                      )
                    }
                  />
                  <Action
                    title="Delete from State"
                    icon={Icon.Trash}
                    style={Action.Style.Destructive}
                    shortcut={{ modifiers: ["cmd"], key: "d" }}
                    onAction={() => handleDeleteDomain(entry.domain)}
                  />
                </ActionPanel>
              }
            />
          ))}
        </List.Section>
        {domains.length === 0 && !showNewDomainOption && (
          <List.EmptyView
            icon={Icon.Key}
            title="No stored domains"
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

${selectedDomain ? `**Domain:** \`${selectedDomain}\`` : ""}

*Waiting for hardware interaction...*`}
      />
    );
  }

  // Stage: Select Username (from cached data, no CLI interaction yet)
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
              subtitle="New username (requires state unlock)"
              actions={
                <ActionPanel>
                  <Action
                    title="Use This Username"
                    onAction={() =>
                      startProcess(
                        selectedDomain,
                        usernameSearch,
                        selectedVersion,
                        true, // new username always needs state unlock
                      )
                    }
                  />
                </ActionPanel>
              }
            />
          )}

          {/* Existing usernames from cached data */}
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
                      if (entry.isDomainOnly) {
                        // Domain-only: needs state unlock only if new domain
                        startProcess(
                          selectedDomain,
                          undefined,
                          selectedVersion,
                          isNewDomain,
                        );
                      } else {
                        // Existing username: no state unlock needed
                        startProcess(
                          selectedDomain,
                          entry.name,
                          selectedVersion,
                          false,
                        );
                      }
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
                setOutput("");
                setError("");
                setUsernames([]);
                setUsernameSearch("");
                setSelectedUsername("");
                setSelectedDomain("");
                processRef.current?.kill();
                processRef.current = null;
                loadDomainsFromState();
              }}
            />
          </ActionPanel>
        }
      />
    );
  }

  return <Detail markdown="Loading..." />;
}

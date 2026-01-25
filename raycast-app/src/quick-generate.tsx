import {
  Action,
  ActionPanel,
  Detail,
  Form,
  LaunchProps,
  getPreferenceValues,
  showHUD,
  popToRoot,
} from "@raycast/api";
import { spawn, ChildProcess } from "child_process";
import { useState, useEffect, useCallback, useRef } from "react";

interface Arguments {
  domain: string;
  username?: string;
}

interface Preferences {
  binaryPath?: string;
}

// Comprehensive PATH for macOS
const MACOS_PATH = [
  "/opt/homebrew/bin",
  "/usr/local/bin",
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
  | "starting"
  | "unlock-touch"
  | "password-touch"
  | "enter-pin"
  | "success"
  | "error";

export default function QuickGenerate(
  props: LaunchProps<{ arguments: Arguments }>,
) {
  const { domain, username } = props.arguments;

  let binaryPath = "password-generator";
  try {
    const prefs = getPreferenceValues<Preferences>();
    if (prefs.binaryPath) {
      binaryPath = prefs.binaryPath;
    }
  } catch {
    // No preferences defined, use default
  }

  const [stage, setStage] = useState<Stage>("starting");
  const [, setOutput] = useState<string>("");
  const [error, setError] = useState<string>("");

  const processRef = useRef<ChildProcess | null>(null);
  const outputBufferRef = useRef<string>("");
  const stderrBufferRef = useRef<string>("");

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

  // Start process on mount
  useEffect(() => {
    if (processRef.current) return;

    const args = username ? [domain, "-u", username] : [domain];

    const proc = spawn(binaryPath, args, {
      env: { ...process.env, PATH: MACOS_PATH },
    });

    processRef.current = proc;

    proc.stdout?.on("data", (data: Buffer) => {
      const text = data.toString();
      outputBufferRef.current += text;
      setOutput((prev) => prev + text);

      if (text.includes("copied to clipboard")) {
        setStage("success");
        showHUD("✅ Password copied to clipboard!");
        setTimeout(() => popToRoot(), 1000);
      }
    });

    proc.stderr?.on("data", (data: Buffer) => {
      const text = data.toString();
      stderrBufferRef.current += text;

      if (text.includes("Touch YubiKey to unlock state")) {
        setStage("unlock-touch");
      } else if (text.includes("Touch YubiKey for password")) {
        setStage("password-touch");
      } else if (text.includes("Enter PIN:")) {
        setStage("enter-pin");
      } else if (text.includes("copied to clipboard")) {
        setStage("success");
        showHUD("✅ Password copied to clipboard!");
        setTimeout(() => popToRoot(), 1000);
      }
    });

    proc.on("error", (err) => {
      setError(`Spawn error: ${err.message}`);
      setStage("error");
    });

    proc.on("close", (code) => {
      // Only set error if we haven't succeeded and process exited unexpectedly
      if (code !== 0) {
        const allOutput = `STDOUT:\n${outputBufferRef.current}\n\nSTDERR:\n${stderrBufferRef.current}`;
        if (!allOutput.includes("copied to clipboard")) {
          setError(`Exit code: ${code}\n\n${allOutput}`);
          setStage("error");
        }
      }
    });

    return () => {
      // Don't kill on cleanup - let the process complete
    };
  }, [domain, username, binaryPath]);

  const subtitle = username ? `${domain} / ${username}` : domain;

  if (stage === "starting") {
    return (
      <Detail
        markdown={`# Starting...

Launching password-generator for \`${subtitle}\`...`}
      />
    );
  }

  if (stage === "unlock-touch") {
    return (
      <Detail
        markdown={`# 🔑 Touch YubiKey

Touch your YubiKey to unlock state...

**Domain:** \`${domain}\`${username ? `\n**Username:** \`${username}\`` : ""}

*Waiting for hardware interaction...*`}
      />
    );
  }

  if (stage === "password-touch") {
    return (
      <Detail
        markdown={`# 🔑 Touch YubiKey Again

Touch your YubiKey to generate password...

**Domain:** \`${domain}\`${username ? `\n**Username:** \`${username}\`` : ""}

*Waiting for hardware interaction...*`}
      />
    );
  }

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
        <Form.Description title="Domain" text={domain} />
        {username && <Form.Description title="Username" text={username} />}
        <Form.PasswordField
          id="pin"
          title="PIN"
          placeholder="Enter your YubiKey PIN"
          autoFocus
        />
      </Form>
    );
  }

  if (stage === "success") {
    return (
      <Detail
        markdown={`# ✅ Password Generated!

Password for \`${subtitle}\` has been copied to your clipboard.

It will be cleared in 20 seconds.`}
      />
    );
  }

  if (stage === "error") {
    return (
      <Detail
        markdown={`# ❌ Error

\`\`\`
${error}
\`\`\`

**Command:** \`${binaryPath} ${domain}${username ? ` -u ${username}` : ""}\`

**Troubleshooting:**
- Make sure \`ykchalresp\` is installed: \`brew install ykpers\`
- Check that your YubiKey is connected
- Verify the binary path in extension preferences`}
        actions={
          <ActionPanel>
            <Action title="Close" onAction={() => popToRoot()} />
          </ActionPanel>
        }
      />
    );
  }

  return <Detail markdown="Loading..." />;
}

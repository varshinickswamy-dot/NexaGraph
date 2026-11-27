import { useState, type FormEvent } from "react";

type AuthenticatedUser = {
  id: string;
  full_name: string;
  email: string;
  organization_id: string | null;
  role: string;
};

type Props = {
  theme: "dark" | "light";
  onToggleTheme: () => void;
  onAuthenticated: (token: string, user: AuthenticatedUser) => void;
};

const API_URL =
  import.meta.env.VITE_API_URL ||
  import.meta.env.VITE_API_BASE_URL ||
  "http://127.0.0.1:8000";

type Mode = "login" | "register";
type OrganizationMode = "create" | "join";

export default function AuthScreen({
  theme,
  onToggleTheme,
  onAuthenticated,
}: Props) {
  const [mode, setMode] = useState<Mode>("login");
  const [organizationMode, setOrganizationMode] =
    useState<OrganizationMode>("create");

  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organization, setOrganization] = useState("");
  const [invitationCode, setInvitationCode] = useState("");

  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);

  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    setBusy(true);
    setError("");
    setNotice("");

    const endpoint =
      mode === "login" ? "/auth/login" : "/auth/register";

    const payload =
      mode === "login"
        ? {
            email: email.trim(),
            password,
          }
        : {
            full_name: fullName.trim(),
            email: email.trim(),
            password,
            organization_mode: organizationMode,
            ...(organizationMode === "create"
              ? { organization_name: organization.trim() }
              : { invitation_code: invitationCode.trim() }),
          };

    try {
      const response = await fetch(`${API_URL}${endpoint}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const result = await response.json().catch(() => ({}));

      if (!response.ok) {
        const detail = result.detail;
        const message =
          typeof detail === "string"
            ? detail
            : Array.isArray(detail)
              ? detail.map((item: { msg?: string }) => item.msg).filter(Boolean).join(", ")
              : `Request failed (${response.status})`;

        throw new Error(message || `Request failed (${response.status})`);
      }

      if (mode === "register") {
        const assignedRole =
          typeof result.role === "string" ? result.role : "assigned";

        setNotice(
          organizationMode === "create"
            ? `Organization created successfully. Your account has been assigned ${assignedRole} access. Please sign in.`
            : `You have successfully joined the organization with ${assignedRole} access. Please sign in.`
        );

        setMode("login");
        setPassword("");
        setInvitationCode("");
        setOrganization("");
        return;
      }

      if (!result.access_token || !result.user) {
        throw new Error("Invalid authentication response from server.");
      }

      onAuthenticated(result.access_token, result.user);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Authentication failed."
      );
    } finally {
      setBusy(false);
    }
  }

  function switchMode(next: Mode) {
    setMode(next);
    setError("");
    setNotice("");
    setPassword("");
  }

  function switchOrganizationMode(next: OrganizationMode) {
    setOrganizationMode(next);
    setError("");
    setNotice("");
    setOrganization("");
    setInvitationCode("");
  }

  return (
    <main className={`nx-auth-page ${theme}`}>
      <div className="nx-auth-orb nx-auth-orb-one" />
      <div className="nx-auth-orb nx-auth-orb-two" />

      <header className="nx-auth-topbar">
        <div className="nx-auth-brand">
          <span className="nx-auth-mark">N</span>
          <span>
            NEXAGRAPH <b>AI</b>
          </span>
        </div>

        <button
          type="button"
          className="nx-auth-theme"
          onClick={onToggleTheme}
        >
          {theme === "dark" ? "☀ Light mode" : "☾ Dark mode"}
        </button>
      </header>

      <section className="nx-auth-layout">
        <div className="nx-auth-intro">
          <span className="nx-auth-eyebrow">
            <i />
            ENTERPRISE CYBERSECURITY INTELLIGENCE
          </span>

          <h1>
            See the paths.
            <br />
            <em>Stop the threats.</em>
          </h1>

          <p>
            Understand your attack surface, connect security signals, and
            prioritize the paths that put your organization at risk.
          </p>

          <div className="nx-auth-feature-list">
            <div>
              <span>01</span>
              <div>
                <strong>Attack Path Intelligence</strong>
                <small>Map relationships and identify exposure.</small>
              </div>
            </div>

            <div>
              <span>02</span>
              <div>
                <strong>Unified Security Operations</strong>
                <small>Investigate events, vulnerabilities and incidents.</small>
              </div>
            </div>

            <div>
              <span>03</span>
              <div>
                <strong>Risk-Led Decisions</strong>
                <small>Prioritize response with contextual insights.</small>
              </div>
            </div>
          </div>

          <div className="nx-auth-footnote">
            <span className="nx-auth-pulse" />
            SECURITY OPERATIONS WORKSPACE
          </div>
        </div>

        <div className="nx-auth-card">
          <div className="nx-auth-card-heading">
            <span className="nx-auth-card-kicker">
              {mode === "login" ? "WELCOME BACK" : "GET STARTED"}
            </span>

            <h2>
              {mode === "login"
                ? "Sign in to your workspace"
                : organizationMode === "create"
                  ? "Create your organization"
                  : "Join your organization"}
            </h2>

            <p>
              {mode === "login"
                ? "Enter your credentials to continue."
                : "Choose how you want to access NexaGraph AI."}
            </p>
          </div>

          <div className="nx-auth-tabs">
            <button
              type="button"
              className={mode === "login" ? "active" : ""}
              onClick={() => switchMode("login")}
            >
              Sign in
            </button>

            <button
              type="button"
              className={mode === "register" ? "active" : ""}
              onClick={() => switchMode("register")}
            >
              Register
            </button>
          </div>

          {error && <div className="nx-auth-alert error">{error}</div>}
          {notice && <div className="nx-auth-alert success">{notice}</div>}

          <form className="nx-auth-form" onSubmit={submit}>
            {mode === "register" && (
              <>
                <label>
                  Full name
                  <input
                    type="text"
                    value={fullName}
                    onChange={(event) => setFullName(event.target.value)}
                    placeholder="Your full name"
                    minLength={2}
                    maxLength={150}
                    autoComplete="name"
                    required
                  />
                </label>

                <div className="nx-auth-org-mode">
                  <span className="nx-auth-field-title">
                    Organization access
                  </span>

                  <div className="nx-auth-org-options">
                    <button
                      type="button"
                      className={
                        organizationMode === "create" ? "selected" : ""
                      }
                      onClick={() => switchOrganizationMode("create")}
                      aria-pressed={organizationMode === "create"}
                    >
                      Create organization
                    </button>

                    <button
                      type="button"
                      className={
                        organizationMode === "join" ? "selected" : ""
                      }
                      onClick={() => switchOrganizationMode("join")}
                      aria-pressed={organizationMode === "join"}
                    >
                      Join organization
                    </button>
                  </div>
                </div>

                {organizationMode === "create" ? (
                  <>
                    <label>
                      Organization name
                      <input
                        type="text"
                        value={organization}
                        onChange={(event) =>
                          setOrganization(event.target.value)
                        }
                        placeholder="Your organization"
                        minLength={2}
                        maxLength={200}
                        required
                      />
                      <small className="nx-auth-hint">
                        The organization creator is assigned Organization
                        Admin access.
                      </small>
                    </label>
                  </>
                ) : (
                  <label>
                    Organization invitation code
                    <input
                      type="text"
                      value={invitationCode}
                      onChange={(event) =>
                        setInvitationCode(event.target.value)
                      }
                      placeholder="Paste the invitation code"
                      minLength={20}
                      maxLength={200}
                      autoComplete="off"
                      required
                    />
                    <small className="nx-auth-hint">
                      Use the code sent to your email by your organization
                      administrator. The invitation determines your role.
                    </small>
                  </label>
                )}
              </>
            )}

            <label>
              Work email
              <input
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="name@company.com"
                autoComplete="email"
                required
              />
            </label>

            <label>
              Password
              <div className="nx-auth-password">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Enter your password"
                  minLength={mode === "register" ? 12 : 1}
                  maxLength={128}
                  autoComplete={
                    mode === "login" ? "current-password" : "new-password"
                  }
                  required
                />

                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>

              {mode === "register" && (
                <small className="nx-auth-hint">
                  Minimum 12 characters. Access is assigned securely by the
                  organization workflow; users cannot choose their own role.
                </small>
              )}
            </label>

            <button
              type="submit"
              className="nx-auth-submit"
              disabled={busy}
            >
              {busy
                ? "Please wait..."
                : mode === "login"
                  ? "Sign in securely"
                  : organizationMode === "create"
                    ? "Create organization"
                    : "Join organization"}
              {!busy && <span>→</span>}
            </button>
          </form>

          <div className="nx-auth-card-footer">
            <span className="nx-auth-lock">▣</span>
            Secure workspace authentication
          </div>
        </div>
      </section>

      <footer className="nx-auth-page-footer">
        NEXAGRAPH AI · ENTERPRISE SECURITY INTELLIGENCE
      </footer>
    </main>
  );
}

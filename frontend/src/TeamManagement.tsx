import { useState } from "react";
import type { FormEvent } from "react";
import "./TeamManagement.css";

const AUTH_TOKEN_KEY = "nexagraph-access-token";

const API_URL =
  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

type InvitationResult = {
  invitation_id: string;
  email: string;
  role: string;
  invitation_code: string;
  expires_at: string;
  status: "success" | "error";
  email_sent?: boolean;
  email_status?: "sent" | "failed";
  message?: string;
};

type MemberInvite = {
  id: number;
  email: string;
  role: "SECURITY_ANALYST" | "VIEWER";
};

export default function TeamManagement() {
  const [members, setMembers] = useState<MemberInvite[]>([
    {
      id: 1,
      email: "",
      role: "SECURITY_ANALYST",
    },
  ]);

  const [expiry, setExpiry] = useState(7);
  const [loading, setLoading] = useState(false);

  const [results, setResults] = useState<InvitationResult[]>([]);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const [deliveryMethod, setDeliveryMethod] =
    useState<"email" | "sms">("email");

  function addMember() {
    setMembers((previous) => [
      ...previous,
      {
        id: Date.now() + Math.random(),
        email: "",
        role: "SECURITY_ANALYST",
      },
    ]);
  }

  function removeMember(id: number) {
    setMembers((previous) =>
      previous.filter((member) => member.id !== id)
    );
  }

  function updateMember(
    id: number,
    field: "email" | "role",
    value: string
  ) {
    setMembers((previous) =>
      previous.map((member) =>
        member.id === id
          ? { ...member, [field]: value }
          : member
      )
    );
  }

  async function generateInvitations(
    event: FormEvent<HTMLFormElement>
  ) {
    event.preventDefault();

    setError("");
    setSuccess("");
    setResults([]);

    const validMembers = members.filter((member) =>
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(member.email.trim())
    );

    if (validMembers.length === 0) {
      setError("Enter at least one valid email address.");
      return;
    }

    if (deliveryMethod === "sms") {
      setError(
        "SMS delivery will be enabled after the SMS provider integration."
      );
      return;
    }

    const token = localStorage.getItem(AUTH_TOKEN_KEY);

    if (!token) {
      setError("Your session has expired. Please log in again.");
      return;
    }

    setLoading(true);

    const invitationResults: InvitationResult[] = [];

    try {
      for (const member of validMembers) {
        try {
          const response = await fetch(
            `${API_URL}/auth/invitations`,
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
              },
              body: JSON.stringify({
                email: member.email.trim(),
                role: member.role,
                expires_in_days: expiry,
              }),
            }
          );

          const data = await response.json().catch(() => ({}));

          if (!response.ok) {
            throw new Error(
              data.detail || `Request failed (${response.status})`
            );
          }

          invitationResults.push({
            invitation_id: data.invitation_id,
            email: data.email,
            role: data.role,
            invitation_code: data.invitation_code,
            expires_at: data.expires_at,
            status: "success",
            email_sent: data.email_sent === true,
            email_status: data.email_status === "sent" ? "sent" : "failed",
            message: data.message,
          });
        } catch (err) {
          invitationResults.push({
            invitation_id: crypto.randomUUID(),
            email: member.email,
            role: member.role,
            invitation_code: "",
            expires_at: "",
            status: "error",
            message:
              err instanceof Error
                ? err.message
                : "Invitation failed.",
          });
        }

        setResults([...invitationResults]);
      }

      const successful = invitationResults.filter(
        (result) => result.status === "success"
      ).length;

      setSuccess(
        `${successful} of ${validMembers.length} invitations generated successfully.`
      );
    } finally {
      setLoading(false);
    }
  }

  async function copyCode(code: string) {
    try {
      await navigator.clipboard.writeText(code);
      setSuccess("Invitation code copied successfully.");
    } catch {
      setError("Unable to copy. Please select and copy the code manually.");
    }
  }

  return (
    <section className="team-management">

      <div className="team-heading">
        <div>
          <span className="team-eyebrow">
            ORGANIZATION ADMINISTRATION
          </span>

          <h2>Team Management</h2>

          <p>
            Invite and manage members of your organization.
          </p>
        </div>

        <div className="team-heading-icon">♙</div>
      </div>

      <div className="team-summary">
        <div className="team-summary-card">
          <span>Invitation Channels</span>
          <strong>Email + SMS</strong>
        </div>

        <div className="team-summary-card">
          <span>Bulk Invitations</span>
          <strong>Enabled</strong>
        </div>

        <div className="team-summary-card">
          <span>Default Expiry</span>
          <strong>{expiry} Days</strong>
        </div>
      </div>

      <div className="team-panel">

        <div className="team-panel-heading">
          <div>
            <h3>Invite Organization Members</h3>
            <p>
              Add multiple people and generate individual invitations.
            </p>
          </div>
        </div>

        <form onSubmit={generateInvitations}>

          <div className="delivery-options">

            <label className="delivery-option">
              <input
                type="radio"
                name="delivery"
                value="email"
                checked={deliveryMethod === "email"}
                onChange={() => setDeliveryMethod("email")}
              />

              <span>✉ Email</span>

              <small>Default</small>
            </label>

            <label className="delivery-option">
              <input
                type="radio"
                name="delivery"
                value="sms"
                checked={deliveryMethod === "sms"}
                onChange={() => setDeliveryMethod("sms")}
              />

              <span>▣ SMS</span>

              <small>Coming next</small>
            </label>

          </div>

          <div className="team-form-label">
            <label>Invitation Expiry</label>

            <select
              value={expiry}
              onChange={(event) =>
                setExpiry(Number(event.target.value))
              }
            >
              <option value={1}>1 Day</option>
              <option value={7}>7 Days</option>
              <option value={14}>14 Days</option>
              <option value={30}>30 Days</option>
            </select>
          </div>

          <div className="team-member-inputs">

            <div className="team-table-heading">
              <span>Email Address</span>
              <span>Assigned Role</span>
              <span>Action</span>
            </div>

            {members.map((member) => (

              <div className="team-member-row" key={member.id}>

                <input
                  type="email"
                  required
                  placeholder="member@example.com"
                  value={member.email}
                  onChange={(event) =>
                    updateMember(
                      member.id,
                      "email",
                      event.target.value
                    )
                  }
                />

                <select
                  value={member.role}
                  onChange={(event) =>
                    updateMember(
                      member.id,
                      "role",
                      event.target.value
                    )
                  }
                >
                  <option value="SECURITY_ANALYST">
                    Security Analyst
                  </option>

                  <option value="VIEWER">
                    Viewer
                  </option>
                </select>

                <button
                  type="button"
                  className="remove-member"
                  onClick={() => removeMember(member.id)}
                  disabled={members.length === 1}
                >
                  Remove
                </button>

              </div>

            ))}

          </div>

          <button
            type="button"
            className="add-member-button"
            onClick={addMember}
          >
            + Add Another Member
          </button>

          <div className="team-submit-area">

            <button
              type="submit"
              className="generate-invitations"
              disabled={loading}
            >
              {loading
                ? "Generating Invitations..."
                : "Generate Invitations"}
            </button>

          </div>

        </form>

        {error && (
          <div className="team-error" role="alert">
            {error}
          </div>
        )}

        {success && (
          <div className="team-success" role="status">
            {success}
          </div>
        )}

      </div>

      {results.length > 0 && (

        <div className="team-panel">

          <div className="team-panel-heading">
            <div>
              <h3>Invitation Results</h3>
              <p>
                Each invitation is saved securely. Email status is shown separately below.
              </p>
            </div>
          </div>

          <div className="invitation-results">

            {results.map((result) => (

              <div
                className="invitation-result"
                key={result.invitation_id}
              >

                <div className="invitation-result-top">

                  <div>
                    <strong>{result.email}</strong>

                    <span>{result.role}</span>
                  </div>

                  <span
                    className={
                      result.status === "success"
                        ? "invitation-status success"
                        : "invitation-status failed"
                    }
                  >
                    {result.status === "success"
                      ? "Generated"
                      : "Failed"}
                  </span>

                </div>

                {result.status === "success" ? (
                  <>
                  <div className="invitation-email-status" role="status">
                    <span className={result.email_sent ? "email-delivery-sent" : "email-delivery-failed"}>
                      {result.email_sent ? "Email accepted by Resend" : "Email not sent"}
                    </span>
                    <small>
                      {result.email_sent
                        ? "The email provider accepted the invitation email. Check inbox and spam folders."
                        : result.message || "The invitation is saved, but email could not be submitted. Check the email service configuration."}
                    </small>
                  </div>

                  <div className="invitation-code-area">

                    <code>{result.invitation_code}</code>

                    <button
                      type="button"
                      onClick={() =>
                        void copyCode(result.invitation_code)
                      }
                    >
                      Copy Code
                    </button>

                    <small>
                      Expires:{" "}
                      {new Date(result.expires_at).toLocaleString()}
                    </small>

                  </div>
                  </>
                ) : (

                  <p className="team-error">
                    {result.message}
                  </p>

                )}

              </div>

            ))}

          </div>

        </div>

      )}

      <div className="team-notice">
        <strong>Security notice</strong>

        <p>
          Invitations are single-use and email-bound.
          Recipients must register with the same email address
          used to generate their invitation.
        </p>
      </div>

    </section>
  );
}
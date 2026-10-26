import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { findingsFilterParams, parseStatusParam, TargetNotes, triggerBulkDismiss } from "./TargetDetailPage";

vi.mock("../lib/apiClient", () => ({ apiFetch: vi.fn() }));
const mockedApiFetch = vi.mocked(apiFetch);

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => body } as Response;
}

function renderNotes(notes: string | null) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <TargetNotes targetId="t1" notes={notes} />
    </QueryClientProvider>,
  );
}

describe("TargetNotes", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows a placeholder and an 'Add notes' link when there are no notes yet", () => {
    renderNotes(null);

    expect(screen.getByText("No notes yet.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add notes" })).toBeInTheDocument();
  });

  it("shows the existing notes and an 'Edit' link when notes are present", () => {
    renderNotes("Staging environment, owned by platform team.");

    expect(screen.getByText("Staging environment, owned by platform team.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit" })).toBeInTheDocument();
  });

  it("clicking 'Add notes' reveals a textarea pre-filled with the current value", async () => {
    const user = userEvent.setup();
    renderNotes(null);

    await user.click(screen.getByRole("button", { name: "Add notes" }));

    expect(screen.getByLabelText("Notes")).toHaveValue("");
  });

  it("shows a character counter that tracks typing and caps the textarea at 2000 characters", async () => {
    const user = userEvent.setup();
    renderNotes(null);
    await user.click(screen.getByRole("button", { name: "Add notes" }));

    expect(screen.getByText("0 / 2000")).toBeInTheDocument();
    expect(screen.getByLabelText("Notes")).toHaveAttribute("maxLength", "2000");

    await user.type(screen.getByLabelText("Notes"), "hello");

    expect(screen.getByText("5 / 2000")).toBeInTheDocument();
  });

  it("saving sends a PATCH with the typed notes and leaves edit mode on success", async () => {
    // Notes itself stays a controlled prop from the parent's target query (which this isolated
    // render doesn't have) - what belongs to this component is that it sends the right PATCH and
    // exits edit mode; TargetDetailPage's own invalidateQueries call is what refreshes the prop
    // with the newly-saved value in the real page.
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse({ id: "t1", notes: "new context" }));

    renderNotes(null);
    await user.click(screen.getByRole("button", { name: "Add notes" }));
    await user.type(screen.getByLabelText("Notes"), "new context");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await screen.findByRole("button", { name: "Add notes" }); // back to the (still-stale) read view
    expect(screen.queryByLabelText("Notes")).not.toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/targets/t1", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ notes: "new context" }),
    });
  });

  it("saving an emptied textarea sends a blank string, not an omitted field", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse({ id: "t1", notes: null }));

    renderNotes("old note");
    await user.click(screen.getByRole("button", { name: "Edit" }));
    await user.clear(screen.getByLabelText("Notes"));
    await user.click(screen.getByRole("button", { name: "Save" }));

    await screen.findByRole("button", { name: "Edit" }); // still "old note" until the parent refetches
    expect(screen.queryByLabelText("Notes")).not.toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledWith(
      "/api/v1/targets/t1",
      expect.objectContaining({ body: JSON.stringify({ notes: "" }) }),
    );
  });

  it("Cancel discards the edit and restores the original value on the next edit", async () => {
    const user = userEvent.setup();
    renderNotes("original note");

    await user.click(screen.getByRole("button", { name: "Edit" }));
    await user.clear(screen.getByLabelText("Notes"));
    await user.type(screen.getByLabelText("Notes"), "discarded draft");
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.getByText("original note")).toBeInTheDocument();
    expect(mockedApiFetch).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Edit" }));
    expect(screen.getByLabelText("Notes")).toHaveValue("original note");
  });

  it("shows an error message and stays in edit mode when the save fails", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse(null, { ok: false, status: 500 }));

    renderNotes(null);
    await user.click(screen.getByRole("button", { name: "Add notes" }));
    await user.type(screen.getByLabelText("Notes"), "will fail");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText("Failed to save notes.")).toBeInTheDocument();
    expect(screen.getByLabelText("Notes")).toBeInTheDocument();
  });

  function dispatchBeforeUnload(): BeforeUnloadEvent {
    const event = new Event("beforeunload", { cancelable: true }) as BeforeUnloadEvent;
    window.dispatchEvent(event);
    return event;
  }

  it("warns before an accidental navigation while a note edit is in progress", async () => {
    const user = userEvent.setup();
    renderNotes(null);

    expect(dispatchBeforeUnload().defaultPrevented).toBe(false); // not editing yet

    await user.click(screen.getByRole("button", { name: "Add notes" }));
    expect(dispatchBeforeUnload().defaultPrevented).toBe(false); // editing, but untouched (matches saved "")

    await user.type(screen.getByLabelText("Notes"), "a thought I don't want to lose");
    expect(dispatchBeforeUnload().defaultPrevented).toBe(true);
  });

  it("does not warn once the edit is cancelled or saved", async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValueOnce(jsonResponse({ id: "t1", notes: "saved note" }));

    renderNotes(null);
    await user.click(screen.getByRole("button", { name: "Add notes" }));
    await user.type(screen.getByLabelText("Notes"), "saved note");
    expect(dispatchBeforeUnload().defaultPrevented).toBe(true);

    await user.click(screen.getByRole("button", { name: "Save" }));
    // Back to the read view (the notes prop itself stays stale here, same as the isolated-render
    // caveat noted on the other save-related tests above - what matters for this test is that
    // leaving edit mode on success clears the warning).
    await waitFor(() => expect(screen.queryByLabelText("Notes")).not.toBeInTheDocument());
    expect(dispatchBeforeUnload().defaultPrevented).toBe(false);
  });
});

describe("findingsFilterParams / parseStatusParam", () => {
  // A live UX bug found after FindingsFilterBar gained its third "Dismissed" toggle: both
  // functions here only ever recognized the literal string "RESOLVED", so clicking Dismissed
  // rendered as pressed/active but the status param was silently dropped, leaving the page
  // showing Open findings the whole time. These are the exact regression case.
  it("forwards DISMISSED, not just RESOLVED, in the outgoing query params", () => {
    const params = findingsFilterParams({ severities: [], categories: [], status: "DISMISSED" });
    expect(params.get("status")).toBe("DISMISSED");
  });

  it("forwards RESOLVED too - the case that was already working", () => {
    const params = findingsFilterParams({ severities: [], categories: [], status: "RESOLVED" });
    expect(params.get("status")).toBe("RESOLVED");
  });

  it("omits the status param entirely for OPEN - the server's own default", () => {
    const params = findingsFilterParams({ severities: [], categories: [], status: "OPEN" });
    expect(params.has("status")).toBe(false);
  });

  it("reads DISMISSED back from a URL param, not just RESOLVED", () => {
    expect(parseStatusParam("DISMISSED")).toBe("DISMISSED");
    expect(parseStatusParam("RESOLVED")).toBe("RESOLVED");
  });

  it("defaults anything unrecognized (absent, stale, hand-edited) back to OPEN", () => {
    expect(parseStatusParam(null)).toBe("OPEN");
    expect(parseStatusParam("garbage")).toBe("OPEN");
  });
});

describe("triggerBulkDismiss", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // A product review found triaging dozens of findings meant dismissing each one individually -
  // same Promise.allSettled-over-N-real-requests pattern as TargetsPage's own bulk-scan/bulk-
  // remove, reusing the single-finding dismiss endpoint rather than a dedicated bulk one.
  it("fires one dismiss request per finding id and reports which ones succeeded", async () => {
    mockedApiFetch
      .mockResolvedValueOnce({ ok: true, status: 204, json: async () => undefined } as Response)
      .mockResolvedValueOnce({ ok: true, status: 204, json: async () => undefined } as Response);

    const outcomes = await triggerBulkDismiss(["f1", "f2"]);

    const dismissCall = {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: null }),
    };
    expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/findings/f1/dismiss", dismissCall);
    expect(mockedApiFetch).toHaveBeenCalledWith("/api/v1/findings/f2/dismiss", dismissCall);
    expect(outcomes).toEqual([
      { findingId: "f1", ok: true },
      { findingId: "f2", ok: true },
    ]);
  });

  it("one failure doesn't block the rest - each finding gets its own independent outcome", async () => {
    mockedApiFetch
      .mockResolvedValueOnce({ ok: true, status: 204, json: async () => undefined } as Response)
      .mockResolvedValueOnce({ ok: false, status: 409, json: async () => ({ message: "only an open finding can be dismissed" }) } as Response);

    const outcomes = await triggerBulkDismiss(["f1", "f2"]);

    expect(outcomes).toEqual([
      { findingId: "f1", ok: true },
      { findingId: "f2", ok: false },
    ]);
  });
});

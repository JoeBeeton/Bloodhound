import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AttackSurfaceGraph } from "./AttackSurfaceGraph";
import type { GraphData, GraphNode } from "../lib/attackSurfaceGraph";

const navigateSpy = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateSpy };
});

function node(overrides: Partial<GraphNode> & Pick<GraphNode, "id" | "kind" | "label">): GraphNode {
  return { radius: 10, ...overrides };
}

function graphData(): GraphData {
  const hub = node({ id: "hub", kind: "hub", label: "central-server" });
  const target = node({
    id: "target:t1",
    kind: "target",
    label: "example.com",
    targetType: "OWN",
    grade: "A",
    score: 92,
  });
  const worker = node({ id: "worker:w1", kind: "worker", label: "worker-1", workerStatus: "IDLE" });
  return {
    nodes: [hub, target, worker],
    links: [
      { source: "hub", target: "target:t1" },
      { source: "hub", target: "worker:w1" },
    ],
  };
}

function renderGraph() {
  return render(
    <MemoryRouter>
      <AttackSurfaceGraph data={graphData()} />
    </MemoryRouter>,
  );
}

describe("AttackSurfaceGraph keyboard accessibility", () => {
  it("makes a navigable node (target) a focusable button with a descriptive label", () => {
    renderGraph();

    const targetNode = screen.getByRole("button", { name: /example\.com, OWN, grade A \(92\)/i });
    expect(targetNode).toHaveAttribute("tabindex", "0");
  });

  it("does not make a non-navigable node (hub/worker) focusable or a button", () => {
    renderGraph();

    expect(screen.queryByRole("button", { name: /central-server/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /worker-1/i })).not.toBeInTheDocument();
  });

  it("pressing Enter on a focused node navigates to its href", async () => {
    const user = userEvent.setup();
    renderGraph();

    const targetNode = screen.getByRole("button", { name: /example\.com/i });
    act(() => targetNode.focus());
    await user.keyboard("{Enter}");

    expect(navigateSpy).toHaveBeenCalledWith("/targets/t1");
  });

  it("pressing Space on a focused node also navigates (same activation keys as a native button)", async () => {
    const user = userEvent.setup();
    renderGraph();

    const targetNode = screen.getByRole("button", { name: /example\.com/i });
    act(() => targetNode.focus());
    await user.keyboard(" ");

    expect(navigateSpy).toHaveBeenCalledWith("/targets/t1");
  });

  it("clicking still works too - the keyboard path is additive, not a replacement", async () => {
    const user = userEvent.setup();
    renderGraph();

    await user.click(screen.getByRole("button", { name: /example\.com/i }));

    expect(navigateSpy).toHaveBeenCalledWith("/targets/t1");
  });
});

import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { Login } from "./Login";

vi.mock("../../api/hooks");

describe("Login", () => {
  it("submits the entered username and password", () => {
    const mutate = vi.fn();
    vi.mocked(hooks.useLogin).mockReturnValue({
      mutate,
      isPending: false,
      isError: false,
    } as unknown as ReturnType<typeof hooks.useLogin>);

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Log in" }));

    expect(mutate).toHaveBeenCalledWith(
      { username: "alice", password: "secret" },
      expect.objectContaining({ onSuccess: expect.any(Function) })
    );
  });

  it("shows an error message when the login mutation fails", () => {
    vi.mocked(hooks.useLogin).mockReturnValue({
      mutate: vi.fn(),
      isPending: false,
      isError: true,
    } as unknown as ReturnType<typeof hooks.useLogin>);

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    expect(screen.getByRole("alert")).toHaveTextContent("Invalid username or password.");
  });
});

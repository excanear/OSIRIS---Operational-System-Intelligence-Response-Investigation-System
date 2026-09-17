import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useLogin } from "../../api/hooks";

export function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const login = useLogin();
  const navigate = useNavigate();

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    login.mutate(
      { username, password },
      {
        onSuccess: () => navigate("/"),
      }
    );
  }

  return (
    <div className="login-screen">
      <h1>OSIRIS</h1>
      <form onSubmit={handleSubmit}>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label>
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <button type="submit" disabled={login.isPending}>
          Log in
        </button>
        {login.isError && <p role="alert">Invalid username or password.</p>}
      </form>
    </div>
  );
}

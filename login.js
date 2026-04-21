async function login(email, password) {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ email, password })
  });
  const data = await res.json();
  localStorage.setItem("token", data.token);
  window.location.href = "/dashboard.html";
}

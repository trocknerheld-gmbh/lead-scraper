const USERNAME = "trocknerheld";
// SHA-256 hash of the password (not stored in plaintext)
const PASSWORD_HASH = "7ff057c8e04d5813a50770e7a1838056618e465ae7d5fba416bf04b3a1bf6466";

async function sha256(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

export default async (request, context) => {
  const auth = request.headers.get("authorization");

  if (auth) {
    const parts = auth.split(" ");
    const scheme = parts[0];
    const encoded = parts[1];
    if (scheme === "Basic" && encoded) {
      const decoded = atob(encoded);
      const colonIdx = decoded.indexOf(":");
      if (colonIdx > -1) {
        const user = decoded.substring(0, colonIdx);
        const pass = decoded.substring(colonIdx + 1);
        const passHash = await sha256(pass);
        if (user === USERNAME && passHash === PASSWORD_HASH) {
          return context.next();
        }
      }
    }
  }

  return new Response("Authentifizierung erforderlich", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Lead Scraper"',
    },
  });
};

export const config = { path: "/*" };

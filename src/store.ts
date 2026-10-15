// In-memory data store, seeded with FAKE users only. No real secrets, no DB, no network.
// Data resets every time the server restarts.

export interface User {
  username: string;
  password: string;
  email: string;
  // Active password-reset token state (null when no reset is pending).
  resetToken: string | null;
  resetExpiresAt: number | null; // epoch ms
  resetTokenUsed: boolean;
}

// Seeded fake accounts. Passwords are obviously fake demo values.
const seed: User[] = [
  { username: "alice", password: "alice-password-1", email: "alice@example.test", resetToken: null, resetExpiresAt: null, resetTokenUsed: false },
  { username: "bob",   password: "bob-password-2",   email: "bob@example.test",   resetToken: null, resetExpiresAt: null, resetTokenUsed: false },
  { username: "carol", password: "carol-password-3", email: "carol@example.test", resetToken: null, resetExpiresAt: null, resetTokenUsed: false },
];

const users = new Map<string, User>(seed.map((u) => [u.username, { ...u }]));

export function getUser(username: string): User | undefined {
  return users.get(username);
}

export function userExists(username: string): boolean {
  return users.has(username);
}

export function allUsernames(): string[] {
  return [...users.keys()];
}

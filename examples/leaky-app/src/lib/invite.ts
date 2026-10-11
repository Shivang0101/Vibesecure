// Invite codes let people join a private team, so they must be unguessable.
export function createInviteCode(): string {
  const inviteCode = Math.random().toString(36).slice(2, 10);
  return inviteCode;
}

// Shuffling a list is fine with Math.random().
export function shuffle<T>(items: T[]): T[] {
  return [...items].sort(() => Math.random() - 0.5);
}
